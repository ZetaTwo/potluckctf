<script>
    import url from "$lib/url";

    let username, password, gender = "", team = "", is_public = true;
    let msg = ""

    async function send() {
        let res = await fetch(url + "/api/register.php", {
            method: "POST",
            body: JSON.stringify({username, password, gender, team, is_public})
        })
        console.log(JSON.stringify({username, password, gender, team, is_public}))
        msg = await res.text();
    }
</script> 

<div class="flex gap-4 flex-row flex-wrap max-w-[700px] mx-auto">

    <label class="form-control w-full max-w-xs">
        <div class="label">
            <span class="label-text">Username (has to be unique)</span>
        </div>
        <input type="text" bind:value={username} class="input input-bordered w-full max-w-xs"/>
    </label>

    <label class="form-control w-full max-w-xs">
        <div class="label">
            <span class="label-text">Password (has to be unique, a-z/A-Z/0-9/_)</span>
        </div>
        <input type="password" bind:value={password} class="input input-bordered w-full max-w-xs"/>
    </label>

    <label class="form-control w-full max-w-xs">
        <div class="label">
            <span class="label-text">Team (optional)</span>
        </div>
        <input type="text" bind:value={team} class="input input-bordered w-full max-w-xs"/>
    </label>

    <label class="form-control w-full max-w-xs">
        <div class="label">
            <span class="label-text">Gender (optional)</span>
        </div>
        <input type="text" bind:value={gender} class="input input-bordered w-full max-w-xs"/>
    </label>

    <div class="form-control w-full max-w-xs">
        <label class="label cursor-pointer">
            <span class="label-text pl-1">Public account</span>
            <input type="checkbox" bind:checked={is_public} class="checkbox"/>
        </label>
        <div class="text-xs text-center opacity-75">
            <i>Just for fun. This is <b>not</b> required to get the flag.</i><br>
            If you set your account to Public, others will be able to find you
            and send postcards to you! If you receive too much spam or want to play
            without distractions, uncheck this checkbox and you won't receive any
            cards from others.
        </div>
    </div>

    <div class="form-control w-full max-w-xs">
        <button class="btn btn-primary" on:click={send}>Register</button>
    </div>

    <div class="max-w-[41rem] w-full text-center">
        {@html msg}
    </div>

</div>


