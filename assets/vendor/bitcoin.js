// Import the elliptic pacakge so we can do ECDSA.
import ellipticjs from '../node_modules/elliptic'

var ec = new ellipticjs.ec('secp256k1');
console.log(ec);