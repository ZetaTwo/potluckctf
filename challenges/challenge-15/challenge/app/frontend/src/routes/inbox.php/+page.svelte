<script>
    import { onMount } from "svelte";
    import Card from "../../lib/Card.svelte";

    let cards = []
    async function init() {
        let res = await fetch('/api/getCards.php')
        cards = await res.json()
    }
    onMount(init)
</script>

<div class="flex flex-col flex-wrap gap-4 items-center justify-center w-full">
    {#each cards as card}
        <div class="w-full max-w-lg">
            <div class="mb-1">
                From {card.slice(1,3).filter(x=>x).join(' at ')}:
            </div>
            <Card preview={card[5]} background={card[6]} />
        </div>
    {/each}
    {#if cards.length === 0}
        <div class="text-2xl">
            No cards yet.
        </div>
    {/if}
</div>