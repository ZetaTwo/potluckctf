const express = require('express');
const puppeteer = require('puppeteer');
const app = express();
const port = 3000;
const flag = process.env.FLAG || 'flag{fake_flag}';

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.post('/', async (req, res) => {
    try {
        const { url } = req.body;
        const parsedUrl = new URL(url);
        console.log(parsedUrl.pathname, parsedUrl.search)
        const newUrl = "http://php" + parsedUrl.search;
        console.log(newUrl);

        const browser = await puppeteer.launch({
            args: ['--no-sandbox']   
        });
        const page = await browser.newPage();
        await page.setCookie({
            name: 'flag',
            value: flag,
            domain: 'php',
            path: '/',
            httpOnly: false,
            secure: false,
            sameSite: 'Strict'
        });
        
        page.on('dialog', async dialog => {
            await dialog.accept();
        });

        await page.goto(newUrl, { waitUntil: 'networkidle2' });

        await browser.close();

        res.send('Site visited!');

    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Something went wrong!');
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});