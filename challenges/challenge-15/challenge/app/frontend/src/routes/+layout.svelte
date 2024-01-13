<script>
    import "../app.pcss";
    import {loggedIn} from "$lib/cookie";
    import {page} from '$app/stores';
    import { brand } from "../lib/brand";

    let links = {
        "/index.php": "Home",
        "/send-card.php": "Send a card",
    };

    async function recheck() {
        let res = await fetch("/api/userInfo.php")
        if (!(await res.json())) {
            location = "/logout.php"
        }
    }

    if (loggedIn) {
        links["/inbox.php"] = "Inbox";
        links["/logout.php"] = "Logout";
        recheck()
    } else {
        links["/login.php"] = "Login";
        links["/register.php"] = "Register";
    }

    $: name = links[$page.url.pathname] || "404";

</script>
<!-- header with navigation -->

<div class="flex flex-col min-h-screen">
    <div class="dummy p-4">&nbsp;</div>
    <header class="w-full bg-secondary text-white p-4 flex fixed z-50">
<!--        always on the top of the page even when scrolling -->
        <div class="flex-1">
            <b>{brand} - {name}</b>
        </div>
        <div class="">
            <nav>
                {#each Object.keys(links) as link}
                    &nbsp; <a href={link} class="link">{links[link]}</a>
                {/each}
            </nav>
        </div>
    </header>

    <!-- main content, at least filling the rest of the screen -->
    <main class="flex-1 p-4" style="background: url('/bg.jpg')">
        <slot></slot>
    </main>
</div>