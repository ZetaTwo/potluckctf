import initSqlJs from 'sql.js';
import type { Database } from 'sql.js';
import type { User } from './fakeDB.js';

const SQL = await initSqlJs();

let globalDB: Database;

// haha, plot twist: the db *is* secure
function genDB() {
    const db = new SQL.Database();
    db.run(`
        drop table if exists users;
        drop table if exists teams;
        drop table if exists cards;

        create table users
        (
            username  varchar(255) primary key not null,
            password  varchar(255)             not null,
            gender    varchar(255),
            team      varchar(255),
            is_public boolean
        );
        insert into users values ('Santa', '${Math.random()}', 'x', '', false);

        create table teams
        (
            teamName varchar(255) primary key not null
        );

        create table cards
        (
            card_id   varchar(255) primary key not null,
            from_user varchar(255),
            from_team varchar(255),
            to_user   varchar(255),
            to_team   varchar(255),
            message   varchar(255),
            background varchar(255)
        );
    `);
    if (globalDB) globalDB.close();
    globalDB = db;
}

genDB();

export function register(u: User) {
    let existing = globalDB.exec(`
        select *
        from users
        where username = @username;
    `, {'@username': u.username});

    if (existing.length > 0) {
        throw new Error('User already exists');
    }

    globalDB.exec(`
        insert into users
        values (@username, @password, 'x', @team, @is_public);
        update teams
        set teamName = @team
        where teamName = @team;
    `, {
        '@username': u.username,
        '@password': u.password,
        '@team': u.team,
        '@is_public': u.is_public ? 1 : 0,
    });
}

export type cardSend = {
    from_user?: string,
    from_team?: string,
    to_user?: string,
    to_team?: string,
    message: string,
    background: string,
}

export function sendCard(c: cardSend) {
    let card_id = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    globalDB.exec(`
        insert into cards
        values (@card_id, @from_user, @from_team, @to_user, @to_team, @message, @background);
    `, {
        '@card_id': card_id,
        '@from_user': c.from_user || null,
        '@from_team': c.from_team || null,
        '@to_user': c.to_user || null,
        '@to_team': c.to_team || null,
        '@message': c.message,
        '@background': c.background,
    });
}

export function getUserInfo(username: string) {
    let res = globalDB.exec(`
        select *
        from users
        where username = @username;
    `, {
        '@username': username,
    });

    return res[0]?.values[0];
}

export function getCards(username: string) {
    let res = globalDB.exec(`
        select *
        from cards
        where to_user = @username
           or UPPER(to_team) = UPPER((select team from users where username = @username))
        limit 10;
    `, {
        '@username': username,
    });
    return res[0]?.values || [];
}

export function checkLogin(username: string, password: string) {
    console.log(username, password)
    let res = globalDB.exec(`
        select *
        from users
        where username = @username
          and password = @password;
    `, {
        '@username': username,
        '@password': password,
    });
    console.log(res)
    return (res[0]?.values?.length || 0) > 0;
}

export function getPlayers() {
    let res = globalDB.exec(`
        select username, team
        from users
        where is_public = 1;
    `);
    return res[0]?.values || null;
}

