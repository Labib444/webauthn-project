import {
  startRegistration,
  startAuthentication,
} from "https://cdn.jsdelivr.net/npm/@simplewebauthn/browser/+esm";

const usernameInput = document.getElementById("username");

document.getElementById("registerBtn").onclick = async () => {
  try {
    const username = usernameInput.value;

    const resp = await fetch("/generate-registration-options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username }),
    });

    const options = await resp.json();

    console.log("Registration options:", options);

    const credential = await startRegistration({
      optionsJSON: options,
    });

    console.log("Credential:", credential);

    const verifyResp = await fetch("/verify-registration", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        credential,
      }),
    });

    const verifyData = await verifyResp.json();

    console.log(verifyData);

    alert(
      verifyData.verified
        ? "Registration successful"
        : "Registration failed"
    );
  } catch (err) {
    console.error(err);
    alert(err.message);
  }
};

document.getElementById("loginBtn").onclick = async () => {
  try {
    const username = usernameInput.value;

    const resp = await fetch("/generate-authentication-options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username }),
    });

    const options = await resp.json();

    const credential = await startAuthentication({
      optionsJSON: options,
    });

    const verifyResp = await fetch("/verify-authentication", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        credential,
      }),
    });

    const verifyData = await verifyResp.json();

    if(verifyData.verified){
        window.location.href = `/dashboard?username=${username}`;
    }else{
        alert("Login failed");
    }
  } catch (err) {
    console.error(err);
    alert(err.message);
  }
};