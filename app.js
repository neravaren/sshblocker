const fs = require('fs'),
    path = require('path'),
    { exec } = require('child_process'),
    ld = require('lodash'),
    moment = require('moment'),
    request = require('request');

const mock = false;
let settings = {};

function ts() {
    return '[' + new moment().format('MMDD HH:mm:ss.SSSS') + ']';
}

function loadSettings() {
    return new Promise((ok, no) => {
        fs.readFile(path.join(__dirname, 'settings.json'), (e, data) => {
            if (e) return no(e);
            settings = JSON.parse(data.toString());
            ok();
        });
    });
}

function loadBlacklist() {
    return new Promise((ok, no) => {
        fs.readFile(path.join(__dirname, 'blacklist.json'), (e, data) => {
            if (e) return no(e);
            ok(JSON.parse(data.toString()));
        });
    });
}

function fillBlacklist(newList, oldList) {
    return ld.unionBy(oldList, newList, 'ip');
}

function saveBlacklist(data) {
    return new Promise((ok, no) => {
        fs.writeFile(path.join(__dirname, 'blacklist.json'), JSON.stringify(data), (e) => {
            if (e) return no(e);
            ok();
        });
    });
}

function getIptablesState() {
    if (mock) return getIptablesStateMock();
    return new Promise((ok, no) => {
        exec(settings.iptablesStateCommand, (e, data) => {
            if (e) return no(e);
            ok(data);
        });
    });
}

function getIptablesStateMock() {
    return new Promise((ok, no) => {
        fs.readFile(path.join(__dirname, 'tests/iptables.response.example2'), (e, data) => {
            if (e) return no(e);
            ok(data.toString());
        });
    });
}

function formatIptablesState(state) {
    let lines = state.replace(/\r\n/g, '\n').split('\n');
    let blockIndex = ld.findIndex(lines, (x) => {
        return x.startsWith('*filter');
    });
    let startIndex = ld.findIndex(lines, (x) => {
        return x.startsWith(':OUTPUT ACCEPT');
    }, blockIndex);
    let endIndex = ld.findIndex(lines, (x) => {
        return x.startsWith('COMMIT');
    }, startIndex);
    let targetBlock = ld.slice(lines, startIndex + 1, endIndex).filter((x) => {
        return x.indexOf(' DROP') !== -1;
    });
    return ld.map(targetBlock, (x) => {
        let match = x.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
        return {ip: match[0]};
    });
}

async function getIptablesBanList() {
    let state = await getIptablesState();
    return formatIptablesState(state);
}

function getAuthLog() {
    if (mock) return getAuthLogMock();
    return new Promise((ok, no) => {
        fs.readFile(settings.authLogFile, (e, data) => {
            if (e) return no(e);
            ok(data.toString());
        });
    });
}

function getAuthLogMock() {
    return new Promise((ok, no) => {
        fs.readFile(path.join(__dirname, 'tests/auth.log3'), (e, data) => {
            if (e) return no(e);
            ok(data.toString());
        });
    });
}

function formatAuthLog(authLog) {
    let lines = authLog.replace(/\r\n/g, '\n').split('\n');
    let rxIp = /Failed password for( invalid user)? (\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
    let rxDate = /^\w+\s+\d+\s+[0-9:]+/;
    let fails = lines.filter((x) => {
        return x.match(rxIp);
    });
    let now = new Date().getFullYear();
    let data = fails.map((x) => {
        return {
            date: new Date(now + ' ' + x.match(rxDate)[0]),
            ip: x.match(rxIp)[3],
            users: [x.match(rxIp)[2]],
            count: 1
        };
    });

    let lastDate = data[data.length-1].date;
    let limitDate = new moment(lastDate).subtract(settings.lookbehindMinutes, 'minutes').toDate();
    console.log(ts(), 'Date range:', lastDate, limitDate);
    data = data.filter((x) => {
        return x.date > limitDate;
    });

    console.log(ts(), `Found ${data.length} shots`);

    let targets = ld.groupBy(data, 'ip');
    let ips = Object.keys(targets);
    let shots = ips.map((key) => {
        let stat = targets[key];
        return ld.reduce(stat, (res, n) => {
            return {
                ip: key,
                date: res.date > n.date ? res.date : n.date,
                count: (res.count||0) + n.count,
                users: ld.uniq(ld.flatten([].concat(res.users||[], n.users)))
            };
        });
    });

    return shots.filter((x) => {
        let limitReached = x.count > settings.maxShotsPerIp;
        if (!limitReached) {
            console.log(ts(), '\t', `${x.ip} not reached limit with ${x.count} shots (${x.users.join(',')})`);
        }
        return limitReached;
    });
}

async function getCurrentState() {
    let authLog = await getAuthLog();
    return formatAuthLog(authLog);
}


function diffBanList(currentState, lastState) {
    // console.log(ts(), 'Difference calculation');
    // console.log(ts(), 'Log', currentState.length, currentState.map((x)=>{return x.ip}).join(' '));
    // console.log(ts(), 'Ipt', lastState.length, lastState.map((x)=>{return x.ip}).join(' '));
    let data = ld.differenceBy(currentState, lastState, (x) => {
        return x.ip;
    });
    // console.log(ts(), 'New', data.length, data.map((x)=>{return x.ip}).join(' '));
    console.log(ts(), `Got ${data.length} new ips`);
    data.forEach((x) => {
        console.log(ts(), '\t', `${x.ip} (${x.count}) (${x.users.join(',')})`);
    });
    return data;
}

function banIp(ip) {
    if (mock) return banIpMock(ip);
    return new Promise((ok, no) => {
        let cmd = settings.banCommand.replace(settings.ipPlaceholder, ip);
        console.log(ts(), '[cmd]', cmd);
        exec(cmd, (e, data) => {
            if (e) return no(e);
            ok(data);
        });
    });
}

function banIpMock(ip) {
    return new Promise((ok, no) => {
        let cmd = settings.banCommand.replace(settings.ipPlaceholder, ip);
        console.log(ts(), '[ban][cmd]', cmd);
        ok();
    });
}

async function banThem(states) {
    for (let state of states) {
        await banIp(state.ip);
    }
}

async function main() {
    await loadSettings();
    let iptablesList = await getIptablesBanList();
    let authList = await getCurrentState();
    let blacklist = await loadBlacklist();

    let banList = fillBlacklist(authList, blacklist);
    let newList = diffBanList(banList, iptablesList);
    await banThem(newList);

    await saveBlacklist(banList);
}

main()
    .then(() => {
        console.log(ts(), 'Done');
    })
    .catch((e) => {
        console.error(ts(), e);
    });
