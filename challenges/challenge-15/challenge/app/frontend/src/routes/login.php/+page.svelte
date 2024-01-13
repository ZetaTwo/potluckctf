<script>
    import url from "$lib/url";
    import {recheckLogin} from "$lib/cookie";

    let username, password;
    let msg = ""

    async function send() {
        let res = await fetch(url + "/api/login.php", {
            method: "POST",
            body: JSON.stringify({username, password})
        })
        if ((await res.text()) === "true") {
            location = "/index.php"
        } else {
            msg = "Login failed";
        }
    }

</script>

<div class="flex gap-4 flex-col flex-wrap max-w-xs mx-auto">
    <label class="form-control w-full max-w-xs">
        <div class="label">
            <span class="label-text">Username</span>
        </div>
        <input type="text" bind:value={username} class="input input-bordered w-full max-w-xs"/>
    </label>

    <label class="form-control w-full max-w-xs">
        <div class="label">
            <span class="label-text">Password</span>
        </div>
        <input type="password" bind:value={password} class="input input-bordered w-full max-w-xs"/>
    </label>

    <div class="form-control w-full max-w-xs">
        <button class="btn btn-primary" on:click={send}>Login</button>
    </div>

    <div class="form-control w-full max-w-xs">
        {msg}
    </div>
</div>