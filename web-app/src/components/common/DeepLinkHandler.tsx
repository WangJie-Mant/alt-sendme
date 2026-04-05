import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useNavigate } from "react-router-dom";
import { routeFromPayload, type DeepLinkPayload } from "@/lib/deepLink";
import { useSenderStore } from "@/store/sender-store";

/**
 * DeepLinkHandler Component
 * Listens for deep-link events from Rust backend and handles routing/state updates
 */
export function DeepLinkHandler() {
  const navigate = useNavigate();
  const senderViewState = useSenderStore((state) => state.viewState);

  useEffect(() => {
    let disposed = false;
    const cleanupFns: UnlistenFn[] = [];

    const handleDeepLink = (payload: DeepLinkPayload) => {
      if (
        payload.action === "receive" &&
        (senderViewState === "SHARING" || senderViewState === "TRANSPORTING")
      ) {
        return;
      }

      const route = routeFromPayload(payload);
      if (!route) {
        console.warn(`[DeepLinkHandler] Unknown action: ${payload.action}`);
        return;
      }
      navigate(route);
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
      cleanupFns.forEach((unlisten) => unlisten());
    };
  }, [navigate, senderViewState]);

  return null;
}

export default DeepLinkHandler;
