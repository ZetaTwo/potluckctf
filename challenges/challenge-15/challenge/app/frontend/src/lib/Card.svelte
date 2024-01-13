<script>
    export let background, preview;
</script>

<div
    class="inline-imgs aspect-[3/2] w-full max-w-lg rounded-lg bg-white shadow-md print overflow-hidden flex items-center justify-center"
    style="background-image: url('{background}'); background-size: contain;"
>
    <div
        class="text-center"
        style="filter: drop-shadow(0 0 10px #fff) drop-shadow(0 0 5px #fff) drop-shadow(0 0 3px #fff)"
    >
        {@html preview}
    </div>
</div>

<style>
    .inline-imgs :global(img) {
        display: inline;
    }
</style>