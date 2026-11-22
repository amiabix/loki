#pragma once

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

// The Linux runner has one window and one signer session per process.
void register_wallet_channel(FlBinaryMessenger *messenger, GtkWindow *window,
                             GtkOverlay *content, const char *data);
