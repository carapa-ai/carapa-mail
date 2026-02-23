const { spawnSync } = require('child_process');
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
console.log('Testing EICAR:', EICAR);
const result = spawnSync('clamscan', ['--no-summary', '-'], { input: EICAR });
console.log('Exit Code:', result.status);
console.log('Stdout:', result.stdout.toString());
console.log('Stderr:', result.stderr.toString());
