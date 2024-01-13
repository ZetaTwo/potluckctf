import express from 'express';
import { cardSend, checkLogin, getCards, getPlayers, getUserInfo, register, sendCard } from './db.js';
import { fakeRegister, User } from './fakeDB.js';
import fs from "fs/promises"
import cookieParser from "cookie-parser"
import * as path from 'path';
import php from 'http-php';
import * as proc from 'child_process';
import * as util from 'util';
import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';

const __dirname = process.cwd()
const exec = util.promisify(proc.exec);
const window = new JSDOM('').window;
const DP = DOMPurify(window);
const app = express();

const fake_flag_text = "Nice try, but LFI is boring :) find the flag by executing /app/readflag"

app.use((_, res, next) => {
    res.set('X-Powered-By', 'PHP/8.4.2');
    next();
})

app.use(express.text());
app.use(cookieParser())

app.post('/api/register.php', (req, res) => {
    try {
        let result = fakeRegister(JSON.parse(req.body) satisfies User)
        register(JSON.parse(req.body) satisfies User)
        res.send(result)
    } catch (e) {
        res.send((e as Error).message)
    }
})

app.post('/api/login.php', (req, res) => {
    let {username, password} = JSON.parse(req.body);
    let result = checkLogin(username, password);
    if (result) {
        res.cookie('username', username)
        res.cookie('password', password)
    }
    res.json(result)
})

app.get('/api/userInfo.php', (req, res) => {
    console.log(req.cookies)
    try {
        let {username, password} = req.cookies
        if (checkLogin(username, password)) {
            res.json(getUserInfo(username))
        } else {
            res.json(null)
        }
    } catch(e) {
        res.json(null)
    }
})

app.get('/logout.php', (_, res) => {
    res.clearCookie('username')
    res.clearCookie('password')
    res.redirect('/')
})

app.get('/api/getPlayers.php', (_, res) => {
    res.json(getPlayers())
})

app.get('/api/getCards.php', (req, res) => {
    let {username, password} = req.cookies
    if (checkLogin(username, password)) {
        res.json(getCards(username))
    } else {
        res.json([])
    }
})

app.post('/api/sendCard.php', (req, res) => {
    try {
        let {username, password} = req.cookies
        if (checkLogin(username, password)) {
            req.body = JSON.parse(req.body)
            req.body.message = DP.sanitize(req.body.message);
            sendCard(req.body satisfies cardSend)
            res.json(true)
        } else {
            res.json(false)
        }
    } catch(e) {
        console.log("uh oh", e)
        res.send(false)
    }
})

app.get('/', (_, res) => {
    res.redirect('/index.php')
})

app.post('/images/renderLaTeX.php', async (req, res) => {
    console.log("rendering", req.body)
    let uuid = Array(20).fill("").map(_ => Math.floor(Math.random()*27).toString(27)).join("")
    let path = `${__dirname}/images/${uuid}`
    await fs.mkdir(path, {recursive: true})
    await fs.writeFile(`${path}/flag`, fake_flag_text)
    await fs.writeFile(`${path}/flag.txt`, fake_flag_text)
    await fs.writeFile(`${path}/latex.tex`, `
        \\documentclass[18pt]{article}
        \\thispagestyle{empty}
        \\begin{document}
        $ ${req.body} $
        \\end{document}
    `)
    try {
        //                              no hackers allowed :3c
        await exec(`timeout 10 pdflatex -no-shell-escape -interaction=nonstopmode -output-directory ${path} ${path}/latex.tex`)
        await exec(`(cd ${path}; timeout 10 pdfcrop ${path}/latex.pdf ${path}/latex.pdf)`)
        await exec(`timeout 10 convert -density 150 ${path}/latex.pdf ${path}/latex.png`)
        res.send(`<img src="/images/${uuid}/latex.png">`)
    } catch (e) {
        let msg = ""
        for (let x of ["code","cmd","stdout","stderr"]) {
            msg += `<b>${x}</b>: ${(e as any)[x]}<br>`
        }
        res.send(`<b>Error rendering LaTeX!</b><br><pre style="text-align: left; white-space: pre-wrap; word-wrap: break-word">${msg}</pre>`)
    }
})

// incredibly ugly but sveltekit doesnt like writing .php,
// and express doesnt like serving .php.html as .php
app.use(async (req, res, next) => {
    let potentialPath = process.cwd() + '/frontend/build' + req.path.replace(/\.php$/, '.php.html')
    try {
        await fs.access(potentialPath);
        res.sendFile(potentialPath);
    } catch(e) {
        next();
    }
});

let php_path = process.argv[2]

// if not handled by anyone else, serve static/php files
app.get(['/static/*', '/images/*', '/frontend/build/*', '/php/*'], async (req, res) => {
    try {
        let p = path.join(__dirname, req.path)
        await fs.access(p)
        if (p.endsWith('.php')) {
            let php_res = await php({
                file: p,
                timeout: 1000,
                cwd: path.dirname(p),
                php: php_path
            })(req)
            res.send(php_res.body || php_res.err)
        } else {
            res.sendFile(p)
        }
    } catch (e) {
        console.log(e)
        res.send('404 Not Found')
    }
})

app.listen(8080)
console.log("listening on 8080")