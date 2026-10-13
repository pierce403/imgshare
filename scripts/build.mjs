import {cpSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
mkdirSync('build/assets/static',{recursive:true});cpSync('static','build/assets/static',{recursive:true});
writeFileSync('build/assets/index.html',readFileSync('templates/index.html'));
writeFileSync('build/assets/deployment.json',JSON.stringify({repository:'pierce403/imgshare',commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),originalHerokuCommit:'427264795ca424868a1482c6663eb1b4433491ee'})+'\n');
writeFileSync('build/assets/_headers','/deployment.json\n  Cache-Control: no-store\n');
