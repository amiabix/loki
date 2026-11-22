#include "my_application.h"

#include <fontconfig/fontconfig.h>

#include <cstring>
#include <initializer_list>

#include "flutter/generated_plugin_registrant.h"
#include "wallet_channel.h"

struct _MyApplication {
  GtkApplication parent_instance;
  char *data;
};

G_DEFINE_TYPE(MyApplication, my_application, GTK_TYPE_APPLICATION)

static void activate(GApplication *application) {
  g_autoptr(FlDartProject) project = fl_dart_project_new();
  // Load the same bundled fonts for native widgets, without installing them.
  for (const auto *font : {"Inter.ttf", "Mono.ttf"}) {
    g_autofree char *path = g_build_filename(
        fl_dart_project_get_assets_path(project), "fonts", font, nullptr);
    FcConfigAppFontAddFile(nullptr, reinterpret_cast<const FcChar8 *>(path));
  }

  auto *window =
      GTK_WINDOW(gtk_application_window_new(GTK_APPLICATION(application)));
  gtk_window_set_title(window, "LokiSigner");
  gtk_window_set_default_size(window, 1280, 720);
  gtk_widget_set_size_request(GTK_WIDGET(window), 980, 620);

  auto *view = fl_view_new(project);
  auto *content = gtk_overlay_new();
  gtk_container_add(GTK_CONTAINER(content), GTK_WIDGET(view));
  gtk_container_add(GTK_CONTAINER(window), content);
  gtk_widget_show_all(content);
  // Avoid showing a black window before the first Flutter frame.
  g_signal_connect_swapped(view, "first-frame", G_CALLBACK(gtk_widget_show),
                           window);
  gtk_widget_realize(GTK_WIDGET(view));
  fl_register_plugins(FL_PLUGIN_REGISTRY(view));
  register_wallet_channel(
      fl_engine_get_binary_messenger(fl_view_get_engine(view)), window,
      GTK_OVERLAY(content), MY_APPLICATION(application)->data);
  gtk_widget_grab_focus(GTK_WIDGET(view));
}

static gboolean local_command_line(GApplication *application,
                                   gchar ***arguments, int *exit_status) {
  auto *self = MY_APPLICATION(application);
  const auto argc = g_strv_length(*arguments);
  if (argc == 1) {
    self->data = g_build_filename(g_get_user_data_dir(), "LokiSigner", nullptr);
  } else if (argc == 3 && std::strcmp((*arguments)[1], "--data") == 0 &&
             g_path_is_absolute((*arguments)[2])) {
    self->data = g_strdup((*arguments)[2]);
  } else {
    g_printerr("Usage: loki_signer [--data /absolute/profile/directory]\n");
    *exit_status = 2;
    return TRUE;
  }
  g_autoptr(GError) error = nullptr;
  if (!g_application_register(application, nullptr, &error)) {
    g_warning("Failed to register: %s", error->message);
    *exit_status = 1;
    return TRUE;
  }
  g_application_activate(application);
  *exit_status = 0;
  return TRUE;
}

static void dispose(GObject *object) {
  g_clear_pointer(&MY_APPLICATION(object)->data, g_free);
  G_OBJECT_CLASS(my_application_parent_class)->dispose(object);
}

static void my_application_class_init(MyApplicationClass *klass) {
  G_APPLICATION_CLASS(klass)->activate = activate;
  G_APPLICATION_CLASS(klass)->local_command_line = local_command_line;
  G_OBJECT_CLASS(klass)->dispose = dispose;
}

static void my_application_init(MyApplication *) {}

MyApplication *my_application_new() {
  g_set_prgname(APPLICATION_ID);
  return MY_APPLICATION(g_object_new(my_application_get_type(),
                                     "application-id", APPLICATION_ID, "flags",
                                     G_APPLICATION_NON_UNIQUE, nullptr));
}
