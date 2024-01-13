import initSqlJs from 'sql.js';

const SQL = await initSqlJs();

const troll = `Did you expect a flag here? This was just bait! ...okay, that was a bit mean, as a reward for your effort check out <a href="/secret/source-code.tar">/secret/source-code.tar</a>`

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
        insert into users
        values ('user1', 'pass1', 'f', 'team2', false);
        insert into users
        values ('admin', '<br><img src="/castle.png"><br>${troll}<br>', 'x', 'team1', true);
        insert into users
        values ('user2', 'pass2', 'm', 'team2', false);

        create table teams
        (
            teamName varchar(255) primary key not null
        );
        insert into teams
        values ('team1');

        create table cards
        (
            card_id   varchar(255) primary key not null,
            from_user varchar(255),
            from_team varchar(255),
            to_user   varchar(255),
            to_team   varchar(255),
            message   varchar(255)
        );
        insert into cards
        values ('card1', 'user1', 'team2', 'user2', 'team2', 'hello');
    `);
    return db;
}

export type User = {
    username: string,
    password: string,
    gender: string,
    team: string,
    is_public: boolean,
}

export function fakeRegister(u: User) {
    let allowed = /^[a-zA-Z0-9_]*$/
    if (!allowed.test(u.username)) {
        throw new Error('Username contains invalid characters. Allowed: a-z, A-Z, 0-9, _');
    }
    if (!allowed.test(u.password)) {
        throw new Error('Password contains invalid characters. Allowed: a-z, A-Z, 0-9, _');
    }
    if (!allowed.test(u.team)) {
        throw new Error('Team contains invalid characters. Allowed: a-z, A-Z, 0-9, _');
    }

    let globalDB = genDB()

    let existing = globalDB.exec(`
        select * from users where username = '${u.username}';
    `);
    if (existing.length > 0) {
        throw new Error('User already exists');
    }

    try {
        // INTENTIONALLY VULNERABLE TO SQL INJECTION
        let res = globalDB.exec(`
            insert into users
            values ('${u.username}', '[redacted]', '${u.gender}', '${u.team}', ${u.is_public ? 1 : 0});
            select *
            from users
            where username = '${u.username}';
        `)[0].values[0];
        globalDB.close()
        return `New user with values ${res} created! You can now log in.`;
    } catch(e) {
        globalDB.close()
        console.log(e)
        throw new Error('User creation failed:' + (e as any).message);
    }
}
