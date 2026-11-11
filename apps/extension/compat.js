(() => {
  const native = globalThis.browser ?? globalThis.chrome;
  if (!native) return;
  const usesPromises = typeof globalThis.browser !== 'undefined';
  const lastErrorMessage = () => {
    try {
      return native.runtime?.lastError?.message || '';
    } catch {
      return '';
    }
  };

  function wrap(fn, thisArg) {
    return (...args) => {
      if (typeof fn !== 'function') {
        return Promise.reject(new Error('browser API is not available'));
      }
      if (usesPromises) return fn.apply(thisArg, args);
      return new Promise((resolve, reject) => {
        try {
          fn.call(thisArg, ...args, (result) => {
            const message = lastErrorMessage();
            if (message) reject(new Error(message));
            else resolve(result);
          });
        } catch (error) {
          reject(error);
        }
      });
    };
  }

  const runtime = native.runtime;
  const storage = native.storage?.local;
  const tabs = native.tabs;
  const windows = native.windows;
  const isFirefox =
    usesPromises && typeof native.runtime?.getBrowserInfo === 'function';

  globalThis.glyxCompat = {
    native,
    isFirefox,
    usesPromises,
    proxy: native.webAuthenticationProxy,
    storageGet: wrap(storage?.get, storage),
    storageSet: wrap(storage?.set, storage),
    sendNative: wrap(runtime?.sendNativeMessage, runtime),
    sendMessage: wrap(runtime?.sendMessage, runtime),
    getURL: (path) => runtime.getURL(path),
    tabsQuery: wrap(tabs?.query, tabs),
    tabsGet: wrap(tabs?.get, tabs),
    tabsSendMessage: wrap(tabs?.sendMessage, tabs),
    tabsCreate: wrap(tabs?.create, tabs),
    windowsCreate: wrap(windows?.create, windows),
    windowsRemove: wrap(windows?.remove, windows)
  };
})();
