<script>
    import { onMount } from "svelte";
    import Card from "../../lib/Card.svelte";
    import AutoComplete from "simple-svelte-autocomplete"
    import { marked } from "marked"

    let ms = (n) => new Promise(r => setTimeout(r,n))

    let preview;
    let input;
    let processed;
    let print = true;
    let background =
        "https://images.unsplash.com/photo-1511970093628-4e9f59378b4d";
    async function gen() {
        processed = input
        for (let [inp, lat] of input.matchAll(/\$([^$]+)\$/g)) {
            try {
                let res = await Promise.race([fetch('/images/renderLaTeX.php', {
                    method: "POST",
                    body: lat,
                }), (async () => {
                    await ms(30000)
                    return {
                        text: () => ("LaTeX rendering timed out. The server might be overloaded, try again in a bit :(")
                    } 
                })()])
                processed = processed.replace(inp, await res.text())
            } catch (e) {
                processed = processed.replace(inp, `<b>Rendering error</b>`)
            }
        }
        processed = await marked.parse(processed)
        preview = `${processed}`;
    }
    let userInfo = null
    let players = []
    let teams = []
    function dedup(a) {
        return Array.from(new Set(a))
    }
    async function init() {
        let res = await fetch('/api/userInfo.php')
        userInfo = await res.json()
        let res2 = await fetch('/api/getPlayers.php')
        players = await res2.json()
        if (!players) players = []
        teams = dedup(players.map(e=>e[1]))
    }
    let from = 0
    let msg = ""
    onMount(()=>{init()})
    async function send() {
        if (print) {
            window.print()
        } else {
            let res = {
                from_user: (from < 2) ? userInfo[0] : undefined,
                from_team: (from >= 1) ? userInfo[3] : undefined,
                to_user: toSel === 0 ? userInfo[0] :
                    toSel == 2 ? toPlayer : undefined,
                to_team: toSel == 1 ? toTeam : undefined,
                message: processed,
                background
            }
            let resp = await fetch('/api/sendCard.php', {method: "POST", body: JSON.stringify(res)})
            let success = await resp.json()
            msg = success ? "Card sent!" : "Something went wrong."
        }
    }
    let toSel = 0
    let toTeam
    let toPlayer
    let eq = `$\\frac {fancy} {equation}$`
</script>

<div class="max-w-lg mx-auto flex flex-col gap-2">
    <label class="form-control">
        <div class="label">
            <span class="label-text"
                >Card text. Supports usual Markdown syntax and LaTeX (if you're
                someone who sends math problems on Christmas, we got you covered
                with PDFLaTeX!)</span
            >
        </div>
        <textarea
            class="textarea textarea-bordered h-24"
            bind:value={input}
            placeholder="Your *fancy* text (or {eq}) here"
        ></textarea>
    </label>
    <label class="form-control">
        <div class="label">
            <span class="label-text">Background image</span>
        </div>
        <input class="input input-bordered w-full" bind:value={background} />
    </label>

    <button class="btn btn-primary w-full" on:click={gen}>Generate card</button>
    {#if preview}
        <div class="print-container">
            <Card {background} {preview} />
            <div class="print-hint pt-8">
                Select "current page only" and "print backgrounds" to print me!
            </div>
        </div>
        <div>
            <div class="form-control">
                <div class="label">
                    <span class="label-text">
                        Delivery option
                    </span>
                </div>
                <label class="label cursor-pointer w-auto">
                    <input
                        type="radio"
                        name="radio-11"
                        class="radio checked:bg-blue-500"
                        bind:group={print} value={1}
                    />
                    <span class="label-text flex-1 ml-1">Print & deliver yourself</span>
                </label>
                <label class="label cursor-pointer w-auto">
                    <input
                        type="radio"
                        name="radio-11"
                        class="radio checked:bg-blue-500"
                        bind:group={print} value={0}
                        disabled={!userInfo}
                    />
                    <span class="label-text flex-1 ml-1">Send online
                        {#if !userInfo}
                            <span class="badge badge-sm badge-error">Requires&nbsp;<a href="/login.php">login</a></span>
                        {/if}
                    </span>
                </label>
                <label class="label cursor-pointer w-auto">
                    <input
                        type="radio"
                        name="radio-11"
                        class="radio checked:bg-blue-500"
                        bind:group={print} value={2}
                        disabled
                    />
                    <span class="label-text flex-1 ml-1">Reindeer sleigh   <span class="badge badge-sm badge-error">Unavailable</span></span>
                </label>
            </div>
            {#if !print}
                <div class="form-control">
                    <div class="label">
                        <span class="label-text">
                            Send from
                        </span>
                    </div>
                    <label class="label cursor-pointer w-auto">
                        <input
                            type="radio"
                            name="radio-12"
                            class="radio checked:bg-blue-500"
                            bind:group={from} value={0}
                        />
                        <span class="label-text flex-1 ml-1"><b>{userInfo[0]}</b></span>
                    </label>
                    {#if userInfo[3]}
                        <label class="label cursor-pointer w-auto">
                            <input
                                type="radio"
                                name="radio-12"
                                class="radio checked:bg-blue-500"
                                bind:group={from} value={1}
                            />
                            <span class="label-text flex-1 ml-1"><b>{userInfo[0]}</b> at <b>{userInfo[3]}</b></span>
                        </label>
                        <label class="label cursor-pointer w-auto">
                            <input
                                type="radio"
                                name="radio-12"
                                class="radio checked:bg-blue-500"
                                bind:group={from} value={2}
                            />
                            <span class="label-text flex-1 ml-1"><b>{userInfo[3]}</b>
                            </span>
                        </label>
                    {/if}
                </div>
                <div class="form-control">
                    <div class="label">
                        <span class="label-text">
                            Send to
                        </span>
                    </div>
                    <label class="label cursor-pointer w-auto">
                        <input
                            type="radio"
                            name="radio-13"
                            class="radio checked:bg-blue-500"
                            bind:group={toSel} value={0}
                        />
                        <span class="label-text flex-1 ml-1">Yourself</span>
                    </label>
                    <label class="label cursor-pointer w-auto">
                        <input
                            type="radio"
                            name="radio-13"
                            class="radio checked:bg-blue-500"
                            bind:group={toSel} value={1}
                        />
                        <span class="label-text flex-1 ml-1">Team</span>
                        {#if toSel > 0}
                            <AutoComplete items={teams} bind:selectedItem={toTeam} />
                        {/if}
                    </label>
                    <label class="label cursor-pointer w-auto">
                        <input
                            type="radio"
                            name="radio-13"
                            class="radio checked:bg-blue-500"
                            bind:group={toSel} value={2}
                        />
                        <span class="label-text flex-1 ml-1">Player</span>
                        {#if toSel > 1}
                            <AutoComplete bind:selectedItem={toPlayer} items={(toTeam ? players.filter(e=>e[1]===toTeam) : players).map(e=>e[0])} />
                        {/if}
                    </label>
                </div>
            {/if}
            <button class="btn btn-primary w-full" on:click={send}>
                Send
            </button>
            <div class="form-control w-full max-w-xs">
                {msg}
            </div>
        </div>
    {/if}
</div>

<style global>
    @media print {
        .print-container {
            background-color: white;
            height: 100%;
            width: 100%;
            position: fixed;
            top: 0;
            left: 0;
            margin: 0;
            z-index: 999999999999999;
        }
        .print-hint {
            display: block !important;
        }
    }
    .print-hint {
        display: none;
    }
</style>
