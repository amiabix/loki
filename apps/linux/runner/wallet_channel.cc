#include "wallet_channel.h"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <functional>
#include <future>
#include <initializer_list>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

extern "C" {
using Notice = int (*)(const char *, const char *);
using Cancelled = int (*)(const void *);
using Approval = int (*)(const char *, const void *, Cancelled);
using Roster = int (*)(const char *);
using Connect = int (*)(const char *, const char *, const void *, Cancelled);
char *loki_member_app_profile(const char *, unsigned);
char *loki_member_app_pairing_target(const char *);
char *loki_member_app_configuration(const char *);
int loki_member_app_pair(const char *, char *, Notice, Approval, Roster,
                         Connect);
char *loki_member_app_restore_profile(const char *, char *, size_t, char *,
                                      size_t, const char *, const char *,
                                      Notice, Approval, Roster, Connect);
char *loki_member_app_restore_vault(char *, size_t, const char *, const char *);
int loki_member_app_stop();
char *loki_member_app_wallet_request(const char *, const char *, int);
char *loki_member_app_vault_addresses();
void loki_member_app_free(char *);
}

namespace {
using Value = std::unique_ptr<FlValue, decltype(&fl_value_unref)>;
using Call = std::shared_ptr<FlMethodCall>;
GtkWindow *window;
GtkOverlay *content;
FlMethodChannel *channel;
GtkCssProvider *prompt_style;
GtkDialog *file_picker;
struct Prompt {
  GtkWidget *page;
  GtkBox *body, *actions;
  bool must_acknowledge;
  GtkWidget *first_field = nullptr, *previous_focus = nullptr;
  GMainLoop *loop = nullptr;
  int response = GTK_RESPONSE_NONE;

  void finish(int answer) {
    if (response == GTK_RESPONSE_NONE) {
      response = answer;
      g_main_loop_quit(loop);
    }
  }
};
Prompt *active_prompt;
std::string base_launch, notice;
Call starting, locking;
bool running = false, ready = false, closing = false, cleaned = false;
unsigned workers = 0, generation = 0;

// Always queue work on GTK's thread, even if the main context is momentarily
// idle.
template <class F> void post(F fn) {
  g_idle_add_full(
      G_PRIORITY_DEFAULT,
      [](gpointer data) -> gboolean {
        (*static_cast<F *>(data))();
        return G_SOURCE_REMOVE;
      },
      new F(std::move(fn)),
      [](gpointer data) { delete static_cast<F *>(data); });
}

template <class F> auto on_ui(F fn) {
  using R = decltype(fn());
  auto task = std::make_shared<std::packaged_task<R()>>(std::move(fn));
  auto result = task->get_future();
  post([task] { (*task)(); });
  return result.get();
}

template <class F> void work(F fn) {
  ++workers;
  std::thread([fn = std::move(fn)]() mutable {
    fn();
    post([] {
      if (--workers == 0 && closing)
        gtk_widget_destroy(GTK_WIDGET(window));
    });
  }).detach();
}

Value decode(const char *text) {
  g_autoptr(FlJsonMessageCodec) codec = fl_json_message_codec_new();
  g_autoptr(GBytes) bytes =
      text ? g_bytes_new_static(text, strlen(text)) : nullptr;
  return {bytes ? fl_message_codec_decode_message(FL_MESSAGE_CODEC(codec),
                                                  bytes, nullptr)
                : nullptr,
          fl_value_unref};
}

Value reply(char *text) {
  std::unique_ptr<char, decltype(&loki_member_app_free)> owned(
      text, loki_member_app_free);
  return decode(owned.get());
}

std::string encode(FlValue *value) {
  g_autoptr(FlJsonMessageCodec) codec = fl_json_message_codec_new();
  g_autoptr(GBytes) bytes =
      fl_message_codec_encode_message(FL_MESSAGE_CODEC(codec), value, nullptr);
  if (!bytes)
    return {};
  gsize size;
  const auto *data = static_cast<const char *>(g_bytes_get_data(bytes, &size));
  return std::string(data, size);
}

FlValue *get(FlValue *map, const char *key) {
  return map && fl_value_get_type(map) == FL_VALUE_TYPE_MAP
             ? fl_value_lookup_string(map, key)
             : nullptr;
}

std::string text(FlValue *value) {
  return value && fl_value_get_type(value) == FL_VALUE_TYPE_STRING
             ? std::string(fl_value_get_string(value))
             : "";
}

std::string text(FlValue *map, const char *key) { return text(get(map, key)); }
int64_t number(FlValue *map, const char *key) {
  auto *value = get(map, key);
  return value && fl_value_get_type(value) == FL_VALUE_TYPE_INT
             ? fl_value_get_int(value)
             : -1;
}
bool flag(FlValue *map, const char *key) {
  auto *value = get(map, key);
  return value && fl_value_get_type(value) == FL_VALUE_TYPE_BOOL &&
         fl_value_get_bool(value);
}

void set(FlValue *map, const char *key, const std::string &value) {
  fl_value_set_string_take(map, key, fl_value_new_string(value.c_str()));
}

void ok(const Call &call, FlValue *value = nullptr) {
  fl_method_call_respond_success(call.get(), value, nullptr);
}

void fail(const Call &call, const char *message, const char *code = "400") {
  fl_method_call_respond_error(call.get(), code, message, nullptr, nullptr);
}

constexpr const char *kCancelled = "LokiSigner review cancelled.";
constexpr const char *kLocked = "LokiSigner is locked.";
constexpr const char *kFailure = "LokiSigner could not complete the operation.";

// Secrets leave these GTK entries as writable buffers, which
// Rust clears when it consumes them. Clear them here too on cancelled/error
// paths.
struct Secret {
  std::vector<char> bytes;
  ~Secret() {
    if (!bytes.empty())
      explicit_bzero(bytes.data(), bytes.size());
  }
  bool empty() const { return bytes.size() <= 1; }
  void read(GtkEntry *entry) {
    auto *value = gtk_entry_get_text(entry);
    bytes.assign(value, value + strlen(value) + 1);
    gtk_entry_set_text(entry, "");
  }
};

void style_prompts(bool dark) {
  // Match the wallet's LokiColors and controls without styling OS dialogs.
  g_autofree char *css = g_strdup_printf(
      R"css(
    @define-color loki_canvas %s;
    @define-color loki_panel %s;
    @define-color loki_secondary %s;
    @define-color loki_ink %s;
    @define-color loki_muted %s;
    @define-color loki_mint %s;
    @define-color loki_stroke %s;

    .loki-prompt-page { background-color: @loki_canvas; }
    .loki-prompt {
      background-color: @loki_panel;
      border: 1px solid @loki_stroke;
      border-radius: 16px;
      padding: 18px;
      color: @loki_ink;
      font: 13px Inter, sans-serif;
    }
    .loki-prompt viewport { background: transparent; }
    .loki-prompt .loki-kicker {
      color: @loki_mint;
      font: 9px "Martian Mono", monospace;
      letter-spacing: 1.4px;
    }
    .loki-prompt .loki-title { font: 600 31px Inter, sans-serif; }
    .loki-prompt .loki-value {
      background-color: @loki_secondary;
      border: 1px solid @loki_stroke;
      border-radius: 10px;
      padding: 10px 12px;
      font: 11px "Martian Mono", monospace;
    }
    .loki-prompt .loki-field-label { color: @loki_muted; font-size: 12px; }
    .loki-prompt entry, .loki-prompt button {
      background: @loki_secondary;
      color: @loki_ink;
      border: 1px solid @loki_stroke;
      box-shadow: none;
      text-shadow: none;
    }
    .loki-prompt entry {
      border-radius: 10px;
      padding: 0 12px;
      min-height: 36px;
      caret-color: @loki_ink;
    }
    .loki-prompt entry:focus { border-color: @loki_mint; }
    .loki-prompt selection { background: @loki_mint; color: #0a0c10; }
    .loki-prompt button {
      border-radius: 11px;
      padding: 0 14px;
      min-height: 31px;
      font-weight: 600;
      font-size: 12px;
    }
    .loki-prompt button:hover { border-color: @loki_muted; }
    .loki-prompt button:focus { outline: 2px solid @loki_muted; }
    .loki-prompt button.loki-primary { background: @loki_mint; color: #0a0c10; }
    .loki-prompt button.loki-primary:hover { background: shade(@loki_mint, 1.08); }
  )css",
      dark ? "#0a0c10" : "#f6f7f9", dark ? "#12151c" : "#ffffff",
      dark ? "#181c25" : "#f0f2f5", dark ? "#e8eaf0" : "#0a0c10",
      dark ? "#8b93a7" : "#5b6475", dark ? "#2fd8a8" : "#0e9f78",
      dark ? "rgba(255,255,255,0.09)" : "rgba(0,0,0,0.09)");
  gtk_css_provider_load_from_data(prompt_style, css, -1, nullptr);
}

GtkWidget *add_action(Prompt *p, const char *title, int response) {
  auto *button = gtk_button_new_with_label(title);
  gtk_box_pack_start(p->actions, button, FALSE, FALSE, 0);
  g_object_set_data(G_OBJECT(button), "response", GINT_TO_POINTER(response));
  g_signal_connect(button, "clicked",
                   G_CALLBACK(+[](GtkWidget *button, gpointer data) {
                     if (gtk_window_is_active(window))
                       static_cast<Prompt *>(data)->finish(GPOINTER_TO_INT(
                           g_object_get_data(G_OBJECT(button), "response")));
                   }),
                   p);
  return button;
}

Prompt *prompt(const char *title, const char *accept,
               const char *alternative = "Cancel") {
  if (active_prompt || file_picker || closing || locking)
    return nullptr;
  auto *page = gtk_event_box_new();
  // Cover the old wallet body while Flutter switches to the prompt canvas.
  gtk_style_context_add_class(gtk_widget_get_style_context(page),
                              "loki-prompt-page");
  gtk_widget_set_can_focus(page, TRUE);
  // Match the wallet body in main.dart, leaving navigation and status visible.
  gtk_widget_set_margin_start(page, 230);
  gtk_widget_set_margin_end(page, 26);
  gtk_widget_set_margin_top(page, 43);
  gtk_widget_set_margin_bottom(page, 36);

  auto *layout = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
  gtk_style_context_add_class(gtk_widget_get_style_context(layout),
                              "loki-prompt");
  gtk_widget_set_valign(layout, GTK_ALIGN_START);
  gtk_widget_set_margin_top(layout, 17);
  gtk_widget_set_margin_bottom(layout, 12);
  gtk_container_add(GTK_CONTAINER(page), layout);

  auto *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
  gtk_box_pack_start(GTK_BOX(layout), header, FALSE, FALSE, 0);
  auto *section = gtk_label_new("LOCAL SIGNER");
  gtk_label_set_xalign(GTK_LABEL(section), 0);
  gtk_style_context_add_class(gtk_widget_get_style_context(section),
                              "loki-kicker");
  gtk_box_pack_start(GTK_BOX(header), section, FALSE, FALSE, 0);
  auto *heading = gtk_label_new(title);
  gtk_label_set_xalign(GTK_LABEL(heading), 0);
  gtk_label_set_line_wrap(GTK_LABEL(heading), TRUE);
  gtk_style_context_add_class(gtk_widget_get_style_context(heading),
                              "loki-title");
  gtk_box_pack_start(GTK_BOX(header), heading, FALSE, FALSE, 0);

  auto *scroll = gtk_scrolled_window_new(nullptr, nullptr);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER,
                                 GTK_POLICY_AUTOMATIC);
  gtk_scrolled_window_set_propagate_natural_height(GTK_SCROLLED_WINDOW(scroll),
                                                   TRUE);
  gtk_box_pack_start(GTK_BOX(layout), scroll, TRUE, TRUE, 0);
  auto *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
  gtk_container_add(GTK_CONTAINER(scroll), body);
  auto *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
  gtk_widget_set_halign(actions, GTK_ALIGN_END);
  gtk_box_pack_end(GTK_BOX(layout), actions, FALSE, FALSE, 0);

  auto *p = new Prompt{page, GTK_BOX(body), GTK_BOX(actions), !alternative};
  if (alternative)
    add_action(p, alternative, GTK_RESPONSE_CANCEL);
  auto *primary = add_action(p, accept, GTK_RESPONSE_ACCEPT);
  gtk_style_context_add_class(gtk_widget_get_style_context(primary),
                              "loki-primary");
  gtk_overlay_add_overlay(content, page);
  return active_prompt = p;
}

void label(Prompt *d, const std::string &value, bool selectable = false,
           int scroll_height = 0) {
  auto *item = gtk_label_new(
      value.c_str()); // Plain text: never interpret coordinator data as markup.
  gtk_label_set_xalign(GTK_LABEL(item), 0);
  gtk_label_set_yalign(GTK_LABEL(item), 0);
  gtk_label_set_line_wrap(GTK_LABEL(item), TRUE);
  gtk_label_set_line_wrap_mode(GTK_LABEL(item), PANGO_WRAP_WORD_CHAR);
  gtk_label_set_max_width_chars(GTK_LABEL(item), 64);
  gtk_label_set_selectable(GTK_LABEL(item), selectable);
  if (selectable)
    gtk_style_context_add_class(gtk_widget_get_style_context(item),
                                "loki-value");
  if (scroll_height) {
    auto *scroll = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(scroll),
                                               scroll_height);
    gtk_scrolled_window_set_propagate_natural_height(
        GTK_SCROLLED_WINDOW(scroll), TRUE);
    gtk_container_add(GTK_CONTAINER(scroll), item);
    item = scroll;
  }
  gtk_box_pack_start(d->body, item, FALSE, FALSE, 0);
}

GtkEntry *field(Prompt *d, const char *name, int maximum, bool secret = false) {
  auto *item = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(item), maximum);
  if (secret) {
    gtk_entry_set_visibility(GTK_ENTRY(item), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(item), GTK_INPUT_PURPOSE_PASSWORD);
  }
  if (!d->first_field)
    d->first_field = item;
  auto *group = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
  auto *caption = gtk_label_new(name);
  gtk_label_set_xalign(GTK_LABEL(caption), 0);
  gtk_style_context_add_class(gtk_widget_get_style_context(caption),
                              "loki-field-label");
  gtk_label_set_mnemonic_widget(GTK_LABEL(caption), item);
  gtk_box_pack_start(GTK_BOX(group), caption, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(group), item, FALSE, FALSE, 0);
  gtk_box_pack_start(d->body, group, FALSE, FALSE, 0);
  return GTK_ENTRY(item);
}

void prompt_changed(bool active) {
  g_autoptr(FlValue) value = fl_value_new_bool(active);
  fl_method_channel_invoke_method(channel, "nativePromptChanged", value,
                                  nullptr, nullptr, nullptr);
}

int show(Prompt *d) {
  d->previous_focus = gtk_window_get_focus(window);
  d->loop = g_main_loop_new(nullptr, FALSE);
  if (d->must_acknowledge)
    gtk_window_set_deletable(window, FALSE);
  gtk_widget_show_all(d->page);
  gtk_widget_grab_focus(d->first_field ? d->first_field : d->page);
  prompt_changed(true);
  // Keep dispatching GTK and Flutter events while the signer awaits the answer.
  g_main_loop_run(d->loop);
  return d->response;
}

void dismiss(Prompt *d) {
  auto *focus = gtk_window_get_focus(window);
  const bool restore_focus =
      focus && (focus == d->page || gtk_widget_is_ancestor(focus, d->page));
  gtk_widget_destroy(d->page);
  if (d->must_acknowledge)
    gtk_window_set_deletable(window, TRUE);
  if (restore_focus && d->previous_focus && !closing)
    gtk_widget_grab_focus(d->previous_focus);
  g_main_loop_unref(d->loop);
  delete d;
  active_prompt = nullptr;
  prompt_changed(false);
}

void cancel_prompt() {
  if (active_prompt && !active_prompt->must_acknowledge)
    active_prompt->finish(GTK_RESPONSE_CANCEL);
}

bool check(const char *title, const std::string &message, const char *action) {
  auto *d = prompt(title, action);
  if (!d)
    return false;
  label(d, message);
  const bool result = show(d) == GTK_RESPONSE_ACCEPT;
  dismiss(d);
  return result;
}

std::string choose_file(bool save, const std::string &name = {}) {
  if (active_prompt || file_picker || closing || locking)
    return {};
  file_picker = GTK_DIALOG(gtk_file_chooser_dialog_new(
      save ? "Save encrypted LokiSigner backup"
           : "Choose encrypted LokiSigner backup",
      window,
      save ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN,
      "Cancel", GTK_RESPONSE_CANCEL, save ? "Save backup" : "Open backup",
      GTK_RESPONSE_ACCEPT, nullptr));
  gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(file_picker), TRUE);
  if (save)
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(file_picker),
                                      name.c_str());
  g_autofree char *file =
      gtk_dialog_run(file_picker) == GTK_RESPONSE_ACCEPT
          ? gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_picker))
          : nullptr;
  gtk_widget_destroy(GTK_WIDGET(file_picker));
  file_picker = nullptr;
  return file ? file : "";
}

// Rust owns each callback's borrowed data until our UI answer returns. Never
// log or forward recovery words or approval decisions through the Flutter
// channel.
int notify(const char *kind, const char *message) {
  const std::string type(kind);
  if (type == "recovery")
    return on_ui([message] {
      auto *d =
          prompt("Save your 24 recovery words", "I saved my words", nullptr);
      if (!d)
        return 0;
      label(d, "Write these down privately. Keep them separate from the "
               "encrypted backup. Do not record this screen.");
      label(d, message);
      const bool saved = show(d) == GTK_RESPONSE_ACCEPT;
      dismiss(d);
      return saved ? 1 : 0;
    });
  if (type == "ready" || type == "restore-ready" || type == "restore-pending") {
    post([type] {
      if (closing || locking) {
        loki_member_app_stop();
        return;
      }
      ready = true;
      if (type == "restore-pending")
        notice = "Vault restored. Waiting to reconnect to the coordinator.";
      if (auto call = std::exchange(starting, nullptr))
        ok(call);
    });
  } else if (type == "locked") {
    post([] { ready = false; });
  } else if (type == "registration-warning" ||
             type == "payment-fee-unverified") {
    post([type, copy = std::string(message)] {
      notice = type == "payment-fee-unverified"
                   ? "The signer could not verify the fee. No share was signed."
                   : copy;
    });
  }
  return 0;
}

int roster(const char *summary) {
  return on_ui([summary] {
    auto data = decode(summary);
    const auto code = text(data.get(), "roster_code");
    if (!ready || code.empty() || text(data.get(), "network") != "testnet")
      return 0;
    auto *d = prompt("Compare vault roster codes", "Codes match");
    if (!d)
      return 0;
    auto *reject = add_action(d, "Codes differ", GTK_RESPONSE_REJECT);
    gtk_box_reorder_child(d->actions, reject, 1);
    label(
        d,
        "Compare the entire code with every member through a trusted channel.");
    label(d, "Vault: " + text(data.get(), "vault_name") +
                 "\nTestnet • Member " +
                 std::to_string(number(data.get(), "member")) + " • " +
                 std::to_string(number(data.get(), "threshold")) + " of " +
                 std::to_string(number(data.get(), "members")));
    label(d, code, true);
    const auto answer = show(d);
    dismiss(d);
    return answer == GTK_RESPONSE_ACCEPT   ? 1
           : answer == GTK_RESPONSE_REJECT ? 2
                                           : 0;
  });
}

std::string amount(FlValue *data, const char *key) {
  const auto value = number(data, key);
  if (value < 0)
    return "";
  g_autofree auto *formatted =
      g_strdup_printf("%" G_GINT64_FORMAT ".%08" G_GINT64_FORMAT " TAZ",
                      static_cast<gint64>(value / 100000000),
                      static_cast<gint64>(value % 100000000));
  return formatted;
}

int approve(const char *summary, const void *context, Cancelled cancelled) {
  using Clock = std::chrono::steady_clock;
  const auto deadline = Clock::now() + std::chrono::seconds(120);
  return on_ui([=] {
    auto data = decode(summary);
    const auto recipient = text(data.get(), "recipient");
    const auto pay = amount(data.get(), "amount_zat");
    const auto fee = amount(data.get(), "fee_zat");
    const auto change = amount(data.get(), "change_zat");
    if (!ready || cancelled(context) ||
        text(data.get(), "network") != "testnet" ||
        !flag(data.get(), "fee_verified") || recipient.empty() || pay.empty() ||
        fee.empty() || change.empty())
      return 0;
    if (Clock::now() >= deadline)
      return 2;
    auto *d = prompt("Signer review · Approve payment?", "Approve and sign",
                     "Refuse");
    if (!d)
      return 0;
    label(d, "Only approve if these signer-verified details match your "
             "intended payment. No reply in 2 minutes refuses it.");
    label(d, "Recipient (shielded, Testnet)\n" + recipient, true);
    label(d, "Amount: " + pay + "\nVerified fee: " + fee +
                 "\nChange back to vault: " + change);
    label(d, "Vault: " + text(data.get(), "vault_name") + "\nMember " +
                 std::to_string(number(data.get(), "member")) + " • Branch " +
                 text(data.get(), "branch_id") + " • Expires at height " +
                 std::to_string(number(data.get(), "expiry_height")));
    const auto memo = text(data.get(), "memo");
    if (!memo.empty()) {
      label(d, "Memo (sender’s text)");
      label(d, memo, false, 72);
    }
    auto *ids = gtk_expander_new("Signing identifiers");
    auto *values =
        gtk_label_new(("Vault ID: " + text(data.get(), "vault") +
                       "\nPayment ID: " + text(data.get(), "payment") +
                       "\nAttempt ID: " + text(data.get(), "attempt") +
                       "\nSighash: " + text(data.get(), "sighash"))
                          .c_str());
    gtk_style_context_add_class(gtk_widget_get_style_context(values),
                                "loki-value");
    gtk_label_set_xalign(GTK_LABEL(values), 0);
    gtk_label_set_line_wrap(GTK_LABEL(values), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(values), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(values), 64);
    gtk_label_set_selectable(GTK_LABEL(values), TRUE);
    gtk_container_add(GTK_CONTAINER(ids), values);
    gtk_box_pack_start(d->body, ids, FALSE, FALSE, 0);
    std::function<void()> poll = [&] {
      if (cancelled(context) || Clock::now() >= deadline)
        d->finish(GTK_RESPONSE_CANCEL);
    };
    const auto timer = g_timeout_add(
        150,
        [](gpointer callback) -> gboolean {
          (*static_cast<std::function<void()> *>(callback))();
          return G_SOURCE_CONTINUE;
        },
        &poll);
    const auto answer = show(d);
    g_source_remove(timer);
    dismiss(d);
    if (cancelled(context) || !ready || closing || locking)
      return 0;
    if (Clock::now() >= deadline)
      return 2;
    return answer == GTK_RESPONSE_ACCEPT ? 1 : 0;
  });
}

int refuse_connect(const char *, const char *, const void *, Cancelled) {
  return 0;
}

const char *restore_error(std::string code) {
  if (code == "backup-fingerprint-mismatch")
    return "The backup fingerprint does not match.";
  if (code == "invalid-backup")
    return "Choose a valid encrypted LokiSigner backup.";
  if (code == "wrong-profile")
    return "This backup belongs to a different signer profile.";
  if (code == "vault-exists")
    return "This vault is already on this device.";
  if (code == "profile-not-fresh")
    return "Start LokiSigner with a fresh profile to restore this signer.";
  if (code == "roster-unavailable")
    return "The original coordinator’s member roster could not be read.";
  if (code == "roster-mismatch")
    return "This backup does not match a member of the original coordinator.";
  if (code == "restored-but-stopped")
    return "The profile was restored but could not start. Try unlocking it.";
  return "The signer could not restore this backup. Check the words, file and "
         "fingerprint.";
}

std::string restore_origin() {
  auto *d = prompt("Enter the original coordinator", "Continue");
  if (!d)
    return {};
  label(d, "Use the same HTTPS coordinator as the signer you are restoring.");
  auto *origin = field(d, "Original coordinator HTTPS origin", 256);
  const auto result = show(d) == GTK_RESPONSE_ACCEPT
                          ? std::string(gtk_entry_get_text(origin))
                          : "";
  dismiss(d);
  return result;
}

bool recovery_fields(Secret &words, std::string &fingerprint) {
  auto *d = prompt("Restore encrypted vault backup", "Restore vault");
  if (!d)
    return false;
  label(d, "Enter your 24 recovery words and the fingerprint saved separately "
           "from this backup.");
  auto *entry = field(d, "24 recovery words", 1024, true);
  auto *code = field(d, "Backup SHA-256 fingerprint", 128);
  const bool accepted = show(d) == GTK_RESPONSE_ACCEPT;
  if (accepted) {
    words.read(entry);
    fingerprint = gtk_entry_get_text(code);
  }
  dismiss(d);
  return accepted;
}

void start(const std::string &link, bool restore) {
  running = true;
  notice.clear();
  work([link, restore] {
    const auto run = [&]() -> const char * {
      auto launch = decode(base_launch.c_str());
      if (restore) {
        const auto origin = on_ui(restore_origin);
        if (origin.empty())
          return kCancelled;
        set(launch.get(), "restore_origin", origin);
      } else if (!link.empty()) {
        set(launch.get(), "pairing_url", link);
      }
      if (restore || !link.empty()) {
        auto checked =
            reply(loki_member_app_pairing_target(encode(launch.get()).c_str()));
        auto *target = get(checked.get(), "target");
        if (!target)
          return restore ? "Enter the original coordinator’s HTTPS origin."
                         : "The one-use pairing link is invalid or belongs to "
                           "another profile.";
        const auto origin = text(target, "coordinator");
        const auto slot = number(target, "slot");
        if (!on_ui([&] {
              return check(
                  restore ? "Confirm original coordinator"
                          : "Confirm member slot",
                  "Coordinator: " + origin +
                      (restore ? ""
                               : "\nMember slot: " + std::to_string(slot)) +
                      "\n\nContinue only if you intended to contact this "
                      "coordinator.",
                  "Continue");
            }))
          return kCancelled;
      }
      auto preview =
          reply(loki_member_app_configuration(encode(launch.get()).c_str()));
      auto *config = get(preview.get(), "config");
      if (!config)
        return "Could not read the coordinator’s signer configuration.";
      if (text(config, "network") != "testnet")
        return "LokiSigner only supports public Zcash testnet.";
      auto *witnesses = get(config, "nonce_witnesses");
      if (!witnesses || fl_value_get_type(witnesses) != FL_VALUE_TYPE_LIST ||
          fl_value_get_length(witnesses) != 2)
        return "A pair of HTTPS nonce witnesses is required.";
      if (flag(config, "confirm_witness_fingerprint")) {
        const auto fingerprint = on_ui([] {
          auto *d = prompt("Verify the nonce witnesses", "Verify witnesses");
          if (!d)
            return std::string();
          label(d, "Enter the pair fingerprint from the witness operators "
                   "through a trusted channel, not from the wallet.");
          auto *input = field(d, "Witness pair fingerprint", 128);
          std::string code =
              show(d) == GTK_RESPONSE_ACCEPT ? gtk_entry_get_text(input) : "";
          dismiss(d);
          return code;
        });
        if (fingerprint.empty())
          return kCancelled;
        if (g_ascii_strcasecmp(fingerprint.c_str(),
                               text(config, "witness_fingerprint").c_str()) !=
            0)
          return "The nonce witness fingerprint did not match. Confirm it with "
                 "the operators.";
        set(launch.get(), "witness_confirmation", fingerprint);
      }
      const auto endpoints =
          "Coordinator: " + text(config, "coordinator") +
          "\nNetwork: Testnet\nFROST relay: " + text(config, "frostd_url") +
          "\nLightwalletd: " + text(config, "lightwalletd_url") +
          "\nNonce witnesses:\n" + text(fl_value_get_list_value(witnesses, 0)) +
          "\n" + text(fl_value_get_list_value(witnesses, 1));
      Secret pass;
      std::string profile_name;
      if (!on_ui([&] {
            auto *d = prompt(restore        ? "Review restore configuration"
                             : link.empty() ? "Unlock signer"
                                            : "Review signer configuration",
                             restore        ? "Continue"
                             : link.empty() ? "Unlock"
                                            : "Pair signer");
            if (!d)
              return false;
            label(d, endpoints);
            label(d, "Your passphrase protects the local software signer. "
                     "Unlocking does not approve any payment.");
            auto *name = !link.empty() ? field(d, "Profile name (optional)", 80)
                                       : nullptr;
            auto *entry = field(d, "Local profile passphrase", 1024, true);
            const bool accepted = show(d) == GTK_RESPONSE_ACCEPT;
            if (accepted) {
              if (name)
                profile_name = gtk_entry_get_text(name);
              pass.read(entry);
            }
            dismiss(d);
            return accepted;
          }))
        return kCancelled;
      if (pass.empty())
        return "Enter a non-empty local profile passphrase.";
      if (!profile_name.empty())
        set(launch.get(), "profile_name", profile_name);
      fl_value_set_string(launch.get(), "config", config);
      fl_value_set_string_take(launch.get(), "embedded",
                               fl_value_new_bool(TRUE));
      const auto args = encode(launch.get());
      if (restore) {
        const auto file = on_ui([] { return choose_file(false); });
        Secret words;
        std::string fingerprint;
        if (file.empty() ||
            !on_ui([&] { return recovery_fields(words, fingerprint); }))
          return kCancelled;
        if (words.empty())
          return "Enter the 24 recovery words.";
        auto result = reply(loki_member_app_restore_profile(
            args.c_str(), words.bytes.data(), words.bytes.size() - 1,
            pass.bytes.data(), pass.bytes.size() - 1, file.c_str(),
            fingerprint.c_str(), notify, approve, roster, refuse_connect));
        const auto code = text(result.get(), "error");
        return flag(result.get(), "restored") ? nullptr : restore_error(code);
      }
      switch (loki_member_app_pair(args.c_str(), pass.bytes.data(), notify,
                                   approve, roster, refuse_connect)) {
      case 0:
        return nullptr;
      case 3:
        return "Could not unlock the local profile. Check your passphrase.";
      case 5:
        return "The coordinator refused registration. Check the slot or "
               "request a fresh pairing link.";
      case 6:
        return "Could not reach the coordinator to register this signer.";
      case 8:
        return "Could not read the coordinator’s roster.";
      case 9:
        return "Enter a valid profile name of up to 80 bytes.";
      case 10:
        return kCancelled;
      default:
        return "Could not start the signer. Quit any other app using this "
               "profile and try again.";
      }
    };
    const auto *error = run();
    post([error] {
      running = ready = false;
      ++generation;
      if (auto call = std::exchange(starting, nullptr))
        fail(call, error ? error : kFailure);
      if (auto call = std::exchange(locking, nullptr))
        ok(call);
      if (error && error != kCancelled)
        notice = error;
    });
  });
}

bool hex_id(const std::string &id) {
  return id.size() == 64 &&
         id.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
}

void request(const Call &call, std::string path, std::string body,
             bool export_file) {
  const auto epoch = generation;
  work([=] {
    auto result = reply(loki_member_app_wallet_request(
        path.c_str(), body.empty() ? nullptr : body.c_str(), export_file));
    const auto status = number(result.get(), "status");
    auto *data = get(result.get(), "data");
    if (status < 200 || status >= 300 || !data) {
      const auto error = text(data, "error");
      post([=] {
        fail(call, error.empty() ? kFailure : error.c_str(),
             status == 401 ? "401" : "400");
      });
      return;
    }
    if (!export_file) {
      post([=, json = encode(data)] {
        if (!ready || generation != epoch) {
          fail(call, kLocked, "401");
          return;
        }
        ok(call, decode(json.c_str()).get());
      });
      return;
    }
    const auto id = text(data, "vault");
    const auto fingerprint = text(data, "fingerprint");
    const auto backup = text(data, "backup");
    if (path != "recovery-backup?vault=" + id || !hex_id(id) ||
        !hex_id(fingerprint) || backup.empty() || backup.size() > 255 * 1024) {
      post([=] { fail(call, kFailure); });
      return;
    }
    const auto file = on_ui([&] {
      if (!ready || generation != epoch)
        return std::string();
      auto *d = prompt("Save the backup fingerprint separately",
                       "Choose where to save backup");
      if (!d)
        return std::string();
      label(d, "Keep a trusted copy of this fingerprint separate from the "
               "backup. LokiSigner checks it when you restore.");
      label(d, fingerprint, true);
      const bool accepted = show(d) == GTK_RESPONSE_ACCEPT;
      dismiss(d);
      return accepted ? choose_file(true, "loki-recovery-" + id + ".json") : "";
    });
    g_autoptr(FlValue) portable = fl_value_new_map();
    set(portable, "vault", id);
    set(portable, "backup", backup);
    post([=, json = encode(portable)] {
      if (!ready || generation != epoch) {
        fail(call, kLocked, "401");
        return;
      }
      if (file.empty()) {
        fail(call, kCancelled, "499");
        return;
      }
      // Write once; never replace or follow a symlink to an existing backup.
      const int fd =
          open(file.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd < 0) {
        fail(call, "Could not create the backup. Choose a new filename.");
        return;
      }
      const bool written = write(fd, json.data(), json.size()) ==
                               static_cast<ssize_t>(json.size()) &&
                           fsync(fd) == 0;
      const bool closed = close(fd) == 0;
      if (!written || !closed) {
        unlink(file.c_str());
        fail(call, "Could not save the encrypted backup.");
        return;
      }
      ok(call);
    });
  });
}

void handle(FlMethodChannel *, FlMethodCall *raw, gpointer) {
  const Call call(FL_METHOD_CALL(g_object_ref(raw)), g_object_unref);
  const std::string method = fl_method_call_get_name(raw);
  auto *args = fl_method_call_get_args(raw);
  if (method == "profile") {
    auto profile =
        reply(loki_member_app_profile(base_launch.c_str(), cleaned ? 0 : 1));
    cleaned = true;
    if (text(profile.get(), "profile").empty()) {
      fail(call, "Could not read the local profile directory.");
      return;
    }
    fl_value_set_string_take(profile.get(), "running",
                             fl_value_new_bool(ready));
    ok(call, profile.get());
  } else if (method == "nativePromptActive") {
    g_autoptr(FlValue) value = fl_value_new_bool(active_prompt != nullptr);
    ok(call, value);
  } else if (method == "leaveNativePrompt") {
    if (active_prompt && active_prompt->must_acknowledge) {
      fail(call, "Save your recovery words before leaving this page.", "409");
      return;
    }
    cancel_prompt();
    ok(call);
  } else if (method == "pendingInvite") {
    ok(call);
  } else if (method == "nativeNotice") {
    g_autoptr(FlValue) value =
        notice.empty() ? nullptr : fl_value_new_string(notice.c_str());
    ok(call, value);
  } else if (method == "nativePromptAppearance") {
    if (args && fl_value_get_type(args) == FL_VALUE_TYPE_BOOL)
      style_prompts(fl_value_get_bool(args));
    ok(call);
  } else if (method == "appearance") {
    const auto mode = text(args, "mode");
    auto *settings = gtk_settings_get_default();
    if (mode == "system")
      gtk_settings_reset_property(settings,
                                  "gtk-application-prefer-dark-theme");
    else
      g_object_set(settings, "gtk-application-prefer-dark-theme",
                   mode == "dark", nullptr);
    ok(call);
  } else if (method == "lock") {
    if (locking || starting ||
        (active_prompt && active_prompt->must_acknowledge)) {
      fail(call, "Finish the current signer operation first.", "409");
      return;
    }
    if (!running) {
      ok(call);
      return;
    }
    locking = call;
    ready = false;
    ++generation;
    notice.clear();
    loki_member_app_stop();
    cancel_prompt();
    if (file_picker)
      gtk_dialog_response(file_picker, GTK_RESPONSE_CANCEL);
  } else if (method == "pair" || method == "unlock" ||
             (method == "restore" && !ready)) {
    if (running || closing || active_prompt || file_picker || workers) {
      fail(call, "Finish the current signer operation first.", "409");
      return;
    }
    const auto link = text(args, "link");
    if (method == "pair" && (link.empty() || link.size() > 4096)) {
      fail(call, "Enter the one-use pairing link.");
      return;
    }
    start(link, method == "restore");
    starting = call;
  } else if (!ready) {
    fail(call, kLocked, "401");
  } else if (method == "addresses") {
    const auto epoch = generation;
    work([=] {
      auto result = reply(loki_member_app_vault_addresses());
      auto *rows = get(result.get(), "vaults");
      if (!rows || fl_value_get_type(rows) != FL_VALUE_TYPE_LIST) {
        post([=] { fail(call, "Could not check vault addresses."); });
        return;
      }
      for (size_t i = 0; i < fl_value_get_length(rows); ++i) {
        auto *row = fl_value_get_list_value(rows, i);
        if (get(row, "address") && text(row, "network") != "testnet") {
          fl_value_set_string_take(row, "address", fl_value_new_null());
          set(row, "error", "This vault is not on testnet.");
        }
      }
      post([=, json = encode(rows)] {
        if (!ready || epoch != generation)
          fail(call, kLocked, "401");
        else
          ok(call, decode(json.c_str()).get());
      });
    });
  } else if (method == "request") {
    const auto path = text(args, "path");
    auto *input = get(args, "body");
    const auto body = input ? encode(input) : "";
    if (path.empty() || path.size() > 256 ||
        (input &&
         (fl_value_get_type(input) != FL_VALUE_TYPE_MAP || body.empty())) ||
        body.size() > 1024 * 1024) {
      fail(call, "Invalid wallet request.");
      return;
    }
    request(call, path, body, false);
  } else if (method == "export") {
    auto id = text(args, "vault");
    if (!hex_id(id)) {
      fail(call, "Invalid vault ID.");
      return;
    }
    for (auto &c : id)
      c = g_ascii_tolower(c);
    request(call, "recovery-backup?vault=" + id, "", true);
  } else if (method == "restore") {
    const auto file = choose_file(false);
    auto words = std::make_shared<Secret>();
    std::string fingerprint;
    if (file.empty() || !recovery_fields(*words, fingerprint)) {
      fail(call, kCancelled, "499");
      return;
    }
    if (words->empty()) {
      fail(call, "Enter the 24 recovery words.");
      return;
    }
    if (!ready) {
      fail(call, kLocked, "401");
      return;
    }
    work([=] {
      auto result = reply(loki_member_app_restore_vault(
          words->bytes.data(), words->bytes.size() - 1, file.c_str(),
          fingerprint.c_str()));
      post([=, restored = flag(result.get(), "restored"),
            code = text(result.get(), "error")] {
        if (restored)
          ok(call);
        else
          fail(call, restore_error(code));
      });
    });
  } else if (method == "explorer") {
    const auto txid = text(args, "txid");
    if (!hex_id(txid)) {
      fail(call, "Invalid transaction ID.");
      return;
    }
    if (g_app_info_launch_default_for_uri(
            ("https://testnet.zecblock.com/tx/" + txid).c_str(), nullptr,
            nullptr))
      ok(call);
    else
      fail(call, "Could not open the transaction explorer.");
  } else {
    fl_method_call_respond_not_implemented(raw, nullptr);
  }
}
} // namespace

void register_wallet_channel(FlBinaryMessenger *messenger, GtkWindow *parent,
                             GtkOverlay *host, const char *data) {
  window = parent;
  content = host;
  g_autoptr(GtkCssProvider) css = gtk_css_provider_new();
  prompt_style = css;
  style_prompts(false);
  gtk_style_context_add_provider_for_screen(
      gtk_widget_get_screen(GTK_WIDGET(parent)), GTK_STYLE_PROVIDER(css),
      GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
  g_autoptr(FlValue) launch = fl_value_new_map();
  auto *args = fl_value_new_list();
  for (const auto *arg : {"--data", data, "--port", "0"})
    fl_value_append_take(args, fl_value_new_string(arg));
  fl_value_set_string_take(launch, "args", args);
  base_launch = encode(launch);
  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  channel = fl_method_channel_new(messenger, "cash.loki/wallet",
                                  FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(channel, handle, nullptr, nullptr);
  g_object_set_data_full(G_OBJECT(parent), "loki-wallet-channel", channel,
                         g_object_unref);
  g_signal_connect(
      parent, "key-press-event",
      G_CALLBACK(+[](GtkWidget *, GdkEventKey *event, gpointer) -> gboolean {
        if (!active_prompt)
          return FALSE;
        if (event->keyval == GDK_KEY_Escape) {
          cancel_prompt();
          return TRUE;
        }
        auto *focus = gtk_window_get_focus(window);
        auto *page = active_prompt->page;
        if (!focus || (focus != page && !gtk_widget_is_ancestor(focus, page)))
          return FALSE;
        if (event->keyval == GDK_KEY_Tab ||
            event->keyval == GDK_KEY_ISO_Left_Tab) {
          const auto direction = (event->state & GDK_SHIFT_MASK)
                                     ? GTK_DIR_TAB_BACKWARD
                                     : GTK_DIR_TAB_FORWARD;
          auto *layout = gtk_bin_get_child(GTK_BIN(page));
          if (!gtk_widget_child_focus(layout, direction)) {
            gtk_window_set_focus(window, nullptr);
            gtk_widget_child_focus(layout, direction);
          }
          return TRUE;
        }
        // A keyboard decision requires Space on a focused button, not Return.
        return event->keyval == GDK_KEY_Return ||
               event->keyval == GDK_KEY_KP_Enter;
      }),
      nullptr);
  g_signal_connect(
      parent, "delete-event",
      G_CALLBACK(+[](GtkWidget *, GdkEvent *, gpointer) -> gboolean {
        if (active_prompt && active_prompt->must_acknowledge)
          return TRUE;
        if (workers == 0)
          return FALSE;
        closing = true;
        ready = false;
        gtk_widget_hide(GTK_WIDGET(window));
        loki_member_app_stop();
        cancel_prompt();
        if (file_picker)
          gtk_dialog_response(file_picker, GTK_RESPONSE_CANCEL);
        return TRUE;
      }),
      nullptr);
}
