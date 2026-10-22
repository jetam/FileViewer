// server redirects failed logins to /login?error=<code>.
const MESSAGES = {
  wrong: "Wrong password.",
  locked: "Too many attempts. Try again in a few minutes.",
  full: "The maximum number of people are already signed in. Try again later.",
  expired: "Your session expired. Please sign in again.",
};

const message = MESSAGES[new URLSearchParams(location.search).get("error")];
if (message) {
  const el = document.getElementById("error");
  el.textContent = message;
  el.hidden = false;
}
