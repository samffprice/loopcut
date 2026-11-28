"""Wallet connection controls on Loopcut's provider settings page."""

import threading

import bpy

from . import account, aipass, mainthread

_work: threading.Event | None = None
_message = ""


def draw(column, prefs) -> None:
    if not aipass.client_id():
        column.label(text="Set LOOPCUT_AIPASS_CLIENT_ID to enable this provider.", icon="INFO")
        return
    row = column.row(align=True)
    connected = aipass.connected()
    if _work is not None:
        row.label(text="Waiting for AI Pass…", icon="TIME")
        row.operator("loopcut.aipass_wallet", text="Cancel").action = "CANCEL"
    elif connected:
        row.label(text="AI Pass wallet connected", icon="CHECKMARK")
        row.operator("loopcut.aipass_wallet", text="Disconnect").action = "DISCONNECT"
    else:
        row.operator("loopcut.aipass_wallet", text="Connect AI Pass", icon="URL").action = "CONNECT"
    if _message:
        from . import settings
        for line in settings.wrap(_message, 75):
            column.label(text=line, icon="INFO")
    if connected:
        from . import settings
        row = column.row(align=True)
        row.prop(prefs, "model")
        row.operator("loopcut.fetch_models", text="", icon="FILE_REFRESH")
        if settings.listed_models(prefs.provider):
            row.menu("LOOPCUT_MT_models", text="", icon="DOWNARROW_HLT")


def _finished(cancel: threading.Event, message: str, models: list[str]) -> None:
    global _work, _message
    if _work is not cancel:
        return
    _work, _message = None, message
    from . import settings
    prefs = settings.preferences()
    if prefs is not None and prefs.provider == "AIPASS" and models and not cancel.is_set():
        settings._models[:] = models
        if prefs.model not in models:
            prefs.model = models[0]
    settings.config_changed()
    mainthread.request_redraw()


class LOOPCUT_OT_aipass_wallet(bpy.types.Operator):
    """Connect or disconnect the AI Pass wallet on this computer"""
    bl_idname = "loopcut.aipass_wallet"
    bl_label = "AI Pass Wallet"
    bl_options = {"INTERNAL"}

    action: bpy.props.EnumProperty(items=[
        ("CONNECT", "Connect", ""), ("CANCEL", "Cancel", ""), ("DISCONNECT", "Disconnect", ""),
    ])

    def execute(self, context):
        global _work, _message
        action = self.action
        if _work is not None:
            if action == "CANCEL":
                _work.set()
            return {"CANCELLED"}
        if action == "CANCEL" or not aipass.client_id():
            return {"CANCELLED"}
        cancel = threading.Event()
        _work, _message = cancel, ""

        def run():
            models, message = [], ""
            try:
                if action == "CONNECT":
                    aipass.connect(account.open_browser, cancel.is_set)
                    if not cancel.is_set() and aipass.connected():
                        models = aipass.list_models()
                else:
                    aipass.disconnect()
            except (aipass.WalletError, OSError) as ex:
                message = str(ex) if isinstance(ex, aipass.WalletError) else "Couldn't save the AI Pass connection."
            finally:
                mainthread.run_on_main(lambda: _finished(cancel, message, models))

        threading.Thread(target=run, name="loopcut-aipass-wallet", daemon=True).start()
        mainthread.request_redraw()
        return {"FINISHED"}


def register() -> None:
    bpy.utils.register_class(LOOPCUT_OT_aipass_wallet)


def unregister() -> None:
    if _work is not None:
        _work.set()
    bpy.utils.unregister_class(LOOPCUT_OT_aipass_wallet)
