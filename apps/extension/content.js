function visibleInputs() {
  return [...document.querySelectorAll('input')].filter((el) => {
    if (el.disabled || el.type === 'hidden' || el.type === 'submit') return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  });
}

function classify(inputs) {
  const user = inputs.find(
    (el) =>
      /user|email|login|account/i.test(el.name + el.id + el.autocomplete + el.placeholder) &&
      el.type !== 'password'
  );
  const pass = inputs.find((el) => el.type === 'password');
  const totp = inputs.find(
    (el) =>
      /totp|2fa|otp|authenticator|verification.?code/i.test(el.name + el.id + el.autocomplete) &&
      el !== pass
  );
  return { user, pass, totp };
}

function setValue(el, value) {
  el.focus();
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg.kind === 'probe') {
      const found = classify(visibleInputs());
      reply({ ok: true, hasUser: !!found.user, hasPass: !!found.pass, hasTotp: !!found.totp });
    } else if (msg.kind === 'do-fill') {
      const found = classify(visibleInputs());
      if (msg.username && found.user) setValue(found.user, msg.username);
      if (msg.password && found.pass) setValue(found.pass, msg.password);
      if (msg.totp && found.totp) setValue(found.totp, msg.totp);
      reply({ ok: true, filled: { user: !!found.user, pass: !!found.pass, totp: !!found.totp } });
    } else {
      reply({ ok: false, error: 'unknown message' });
    }
  })().catch((e) => reply({ ok: false, error: String((e && e.message) || e) }));
  return true;
});
