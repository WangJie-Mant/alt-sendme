import { useEffect, useRef } from "react";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useNavigate } from "react-router-dom";
import {
  parseDeepLinkUrl,
  routeFromPayload,
  type DeepLinkPayload,
} from "@/lib/deepLink";

/**
 * DeepLinkHandler Component
 * Listens for deep-link events from Rust backend and handles routing/state updates
 */
export function DeepLinkHandler() {
  const navigate = useNavigate();
  const lastClipboardValueRef = useRef<string | null>(null);
  const isPollingClipboardRef = useRef(false);

  useEffect(() => {
    let disposed = false;
    const cleanupFns: UnlistenFn[] = [];
    let clipboardIntervalId: number | undefined;

    const handleDeepLink = (payload: DeepLinkPayload) => {
      const route = routeFromPayload(payload);
      if (!route) {
        console.warn(`[DeepLinkHandler] Unknown action: ${payload.action}`);
        return;
      }
      navigate(route);
    };

    const pollClipboardForDeepLink = async () => {
      if (isPollingClipboardRef.current) return;
      isPollingClipboardRef.current = true;

      try {
        const clipboardText = (await readText()).trim();
        if (!clipboardText) {
          lastClipboardValueRef.current = null;
          return;
        }

        if (clipboardText === lastClipboardValueRef.current) {
          return;
        }

        lastClipboardValueRef.current = clipboardText;

        const payload = parseDeepLinkUrl(clipboardText);
        if (!payload || payload.action !== "receive" || !payload.ticket) {
          return;
        }

        handleDeepLink(payload);
      } catch (error) {
        console.debug("[DeepLinkHandler] Clipboard polling unavailable", error);
      } finally {
        isPollingClipboardRef.current = false;
      }
    };

    const setupListeners = async () => {
      try {
        const unlistenDeepLink = await listen<DeepLinkPayload>(
          "deep-link",
          (event) => {
            const payload = event.payload;
            console.log("[DeepLinkHandler] Received deep-link event:", {
              action: payload.action,
            });
            handleDeepLink(payload);
          },
        );

        if (disposed) {
          unlistenDeepLink();
          return;
        }
        cleanupFns.push(unlistenDeepLink);

        const unlistenDeepLinkError = await listen<{
          error: string;
          url: string;
        }>("deep-link-error", (event) => {
          console.error(
            "[DeepLinkHandler] Deep link error:",
            event.payload.error,
          );
        });

        if (disposed) {
          unlistenDeepLinkError();
          return;
        }
        cleanupFns.push(unlistenDeepLinkError);

        await pollClipboardForDeepLink();
        clipboardIntervalId = window.setInterval(() => {
          void pollClipboardForDeepLink();
        }, 1500);

        console.log("[DeepLinkHandler] Listeners initialized successfully");
      } catch (error) {
        cleanupFns.forEach((unlisten) => unlisten());
        console.debug(
          "[DeepLinkHandler] Note: Tauri event listener not available",
          error,
        );
      }
    };

    void setupListeners();

    return () => {
      disposed = true;
      if (clipboardIntervalId) {
        window.clearInterval(clipboardIntervalId);
      }
      cleanupFns.forEach((unlisten) => unlisten());
    };
  }, [navigate]);

  return null;
}

export default DeepLinkHandler;
