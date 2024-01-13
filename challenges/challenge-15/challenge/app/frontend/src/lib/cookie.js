import {browser} from "$app/environment";

function getCookies() {
  const cookies = {};
  document.cookie.split(';').forEach((cookie) => {
    const [key, value] = cookie.split('=');
    cookies[key.trim()] = value;
  });
  return cookies;
}

export let loggedIn = false;

export function recheckLogin() {
  if (browser) {
    const cookies = getCookies();
    loggedIn = !!cookies['username'];
  }
}

recheckLogin();


