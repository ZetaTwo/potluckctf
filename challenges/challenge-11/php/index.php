<?php
header("Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval';");

if (isset($_GET["source"])) {
    highlight_file(__FILE__);
    die();
}


$output = "Example output";
if ((isset($_GET["input"]) && !is_null($_GET["input"])) && (isset($_GET["encoding"]) && !is_null($_GET["encoding"]))){
    $input = base64_decode($_GET["input"]);

    if($input === false){
        $output = "Invalid input";
    } else {
        switch ($_GET["encoding"]) {
            case "base64":
                $output = base64_encode($input);
                break;
            case "hex":
                $output = bin2hex($input);
                break;
            case "uu":
                $output = convert_uuencode($input);
                break;
            case "url":
                $output = urlencode($input);
                break;
            case "html":
                $output = htmlentities($input);
                break;
            case "binary":
                $output = implode(array_map(function($c) { return sprintf("%08b", ord($c)); }, str_split($input)));
                break;
            case "ascii":
                $output = implode(array_map(function($c) { return ord($c); }, str_split($input)));
                break;
            default:
                $output = "Invalid encoding";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Encoderchef</title>
    <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
    <h1>Encoderchef</h1>
    <div class="content">
        <div class="input">
            <h2>Input</h2>
                <textarea name="input" id="form-input" placeholder="Enter text to encode here"><?php if (isset($input)) echo $input; ?></textarea><br>
        </div>

        <div class="options">
            <div class="oven">
            </div>
            <img src="icons8-oven-64.png" alt="oven">
        <form method="GET">
            <select name="encoding">
                    <option value="base64" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "base64") { echo "selected"; } ?>>Base64</option>
                    <option value="hex" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "hex") { echo "selected"; } ?>>Hex</option>
                    <option value="uu" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "uu") { echo "selected"; } ?>>UU</option>
                    <option value="url" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "url") { echo "selected"; } ?>>URL</option>
                    <option value="html" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "html") { echo "selected"; } ?>>HTML</option>
                    <option value="binary" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "binary") { echo "selected"; } ?>>Binary</option>
                    <option value="ascii" <?php if (isset($_GET["encoding"]) && $_GET["encoding"] == "ascii") { echo "selected"; } ?>>ASCII</option>
            <input id=hidden-input name=input type=hidden>
            <input type="submit" value="Cook!">
            </form>
        </div>

        <div class="output">
        <h2>Output</h2>
        <div class=output-text>
            <?php echo $output; ?>
        </div>
    </div>

    <script>
        var input = document.querySelector("form");
        input.addEventListener("submit", function(e) {
            var input_value = document.getElementById("form-input")
            var hidden_value = document.getElementById("hidden-input")
            hidden_value.value = btoa(input_value.value);
        });
    </script>
    </div>
    <div class="info">
        <a href="/admin">Admin</a>
        <a href="/?source">Source</a>
    </div>
</body>