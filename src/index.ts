const fs = require("fs");
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const chains = [5, 97];
const values = ["0.1","0.5","1","5","10","100"];

const contractAddress = {
    5: {
        '0.1': "0x157b1854860e48cc51E47abe68E73C51987d43E4",
        '0.5': "0x20438D23D45ec3507b015428C28dA28253C427a1",
        '1': "0x13CA94C7859EF32cBe46721f9A5f69987ea0904C",
        '5': "0x4963D73d4B11bBb8D0275712F7fa6AC332260d90",
        '10': "0xE7BAea860e807add4d3b218218E8050B596A0cE0",
        '100': "0x4e007162335bC6342621DE8ccd24c5EA1B611753"
    },
    97: {
        '0.1': "0x82345BF211F0a502E5134A1D519EC7B1FE1a32Fe",
        '0.5': "0xA387164a4B9c72917Fc3239Eb29f11551D9B8A3B",
        '1': "0x4153bfA84e747012bbAcd97A5b284eca91be96eB",
        '5': "0x4963D73d4B11bBb8D0275712F7fa6AC332260d90",
        '10': "0xE7BAea860e807add4d3b218218E8050B596A0cE0",
        '100': "0x4e007162335bC6342621DE8ccd24c5EA1B611753"
    }
};
const abi = require('./peer.json');

const rpcUrl = {
    1: "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
    5: "https://goerli.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
    56: "https://bsc-dataseed.binance.org",
    97: "https://data-seed-prebsc-1-s1.binance.org:8545"
}

const relayerAddress = "0x37Ee431E0D7f7E9122bE92b7717B31AEF5726667";
const feePercent = 0.01; // 1%
const startBlock = {
    97: 28310830,
    5: 8708125
};

let lastBlock = {
};

let totalEvents = {
    97: {
        "0.1": [],
        "0.5": [],
        "1": []
    },
    5: {
        "0.1": [],
        "0.5": [],
        "1": []    
    }
};

let totalMerkleTrees = {
    97: {
        "0.1": null,
        "0.5": null,
        "1": null
    },
    5: {
        "0.1": null,
        "0.5": null,
        "1": null    
    }
};

const ethers = require('ethers');

const randomBytes = require('crypto').randomBytes;
const circomlib = require('circomlib');
const { bigInt } = require('snarkjs');
const buildGroth16 = require('websnark/src/groth16');
const websnarkUtils = require('websnark/src/utils');
// const MerkleTree = require('fixed-merkle-tree');
const MerkleTree = require('./lib/MerkleTree');
const rbigint = (nbytes) => bigInt.leBuff2int(randomBytes(nbytes));
const MERKLE_TREE_HEIGHT = 20;
// Compute pedersen hash
const pedersenHash = (data) => circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0];

const circuit = require('./withdraw.json');
const proving_key = fs.readFileSync('./withdraw_proving_key.bin').buffer;

// BigNumber to hex string of specified length
const toHex = (number, length = 32) =>
    '0x' + (number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)).padStart(length * 2, '0');

const getNoteStringAndCommitment = () => {
    const nullifier = rbigint(31);
    const secret = rbigint(31);
    // get snarks note and commitment
    const preimage = Buffer.concat([nullifier.leInt2Buff(31), secret.leInt2Buff(31)]);
    let commitment = pedersenHash(preimage);
    const note = toHex(preimage, 62);
    commitment = toHex(commitment);
    return { note, commitment };
};

const createDeposit = (nullifier, secret) => {
    let deposit = { nullifier, secret };
    deposit.preimage = Buffer.concat([deposit.nullifier.leInt2Buff(31), deposit.secret.leInt2Buff(31)]);
    deposit.commitment = pedersenHash(deposit.preimage);
    deposit.nullifierHash = pedersenHash(deposit.nullifier.leInt2Buff(31));
    return deposit;
};

const parseNote = (noteString) => {
    const noteRegex = /peercash-(?<currency>\w+)-(?<amount>[\d.]+)-(?<netId>\d+)-0x(?<note>[0-9a-fA-F]{124})/g;
    let match = noteRegex.exec(noteString);
    if (!match) {
        throw new Error('The note has invalid format');
    }

    let matchGroup = match.groups;
    const buf = Buffer.from(matchGroup.note, 'hex');
    const nullifier = bigInt.leBuff2int(buf.slice(0, 31));
    const secret = bigInt.leBuff2int(buf.slice(31, 62));
    const deposit = createDeposit(nullifier, secret);
    const netId = Number(matchGroup.netId);

    return { currency: matchGroup.currency, amount: matchGroup.amount, netId, deposit: deposit };
};

const generateProof = async ({ chain, value, deposit, recipient, relayerAddress = "0", fee = "0", refund = 0, peer }) => {
    // Compute merkle proof of our commitment
    const { root, path_elements, path_index } = await generateMerkleProof(chain, value, deposit, peer);

    // Prepare circuit input
    const input = {
        // Public snark inputs
        root: root,
        nullifierHash: deposit.nullifierHash,
        recipient: bigInt(recipient),
        relayer: bigInt(relayerAddress),
        fee: bigInt(fee),
        refund: bigInt(refund),

        // Private snark inputs
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: path_elements,
        pathIndices: path_index,
    };

    const groth16 = await buildGroth16();

    // generate proof data
    const proofData = await websnarkUtils.genWitnessAndProve(groth16, input, circuit, proving_key);
    const { proof } = websnarkUtils.toSolidityInput(proofData);
    console.timeEnd('Proof generated. Proof time');

    const args = [
        toHex(input.root),
        toHex(input.nullifierHash),
        toHex(input.recipient, 20),
        toHex(input.relayer, 20),
        toHex(input.fee),
        toHex(input.refund),
    ];

    return { proof, args };
};

async function generateMerkleProof(chain, value, deposit, peer) {
    const tree = totalMerkleTrees[chain][value];

    // Find current commitment in the tree
    const depositEvent = totalEvents[chain][value].find((event) => event.commitment === toHex(deposit.commitment));
    const leafIndex = depositEvent ? depositEvent.leafIndex : -1;

    // Validate that our data is correct
    console.log(new Date().getTime()/1000, "created tree");
    const isValidRoot = await peer.isKnownRoot(toHex(await tree.root()));
    const isSpent = await peer.isSpent(toHex(deposit.nullifierHash));
    if(isValidRoot !== true) {
        throw new Error('Merkle tree is corrupted');
    }
    if(isSpent !== false) {
        throw new Error('The note is already spent');
    }
    if(leafIndex < 0) {
        throw new Error('The deposit is not found in the tree');
    }
    console.log(new Date().getTime()/1000, "spent check");
    // Compute merkle proof of our commitment
    return await tree.path(leafIndex);
}

const SERVER_PORT = 5000;

// create express app
const app = express();

// allow CORS policy so that you can pass data from one localhost port to another during development (otherwise you get an error)
app.use(cors());

// use bodyParser for easier request body manipulation
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

// send created deposit on get request
app.get('/getCommitment', (req, res)=>{
    let data = getNoteStringAndCommitment();
    res.send(JSON.stringify(data));
});

// send parsed data from given note on get request
app.post('/getProof', async (req, res)=>{
    let note = req.body.note;
    let recipient = req.body.recipient;
    if(!note || !recipient)
        return;
    let parsedData = parseNote(note);
    console.log(new Date().getTime()/1000);
    let peerContract = new ethers.Contract(contractAddress[parsedData.netId][parsedData.amount], abi, new ethers.providers.JsonRpcProvider(rpcUrl[parsedData.netId]));
    try
    {
        let data = await generateProof({
            chain: parsedData.netId,
            value: parsedData.amount,
            deposit: parsedData.deposit,
            recipient: req.body.recipient,
            relayerAddress: relayerAddress,
            fee: ethers.utils.parseEther((Number(parsedData.amount)*feePercent).toString()),
            peer: peerContract
        });
        console.log(new Date().getTime()/1000, "end");
        res.send(JSON.stringify([data.proof, ...data.args]));
    } 
    catch (ex)
    {
        res.send(JSON.stringify({failed: true, msg: ex.message}));
    }
});

app.get('/provingKey', function (req, res) {
    res.send(proving_key)
});

app.post('/getEvents', async (req, res)=>{
    let note = req.body.note;
    if(!note)
        return;
    let parsedData = parseNote(note);
    res.send(JSON.stringify({
        events: totalEvents[parsedData.netId][parsedData.amount],
        deposit: parsedData.deposit
    }));
});

// run the server on specified port
const port = process.env.PORT || SERVER_PORT; //
app.listen(port, () => console.log(`Server listening on port ${port}...`));

async function getEvents() {
    const providers = chains.map(async (el)=>{
        const provider = new ethers.providers.JsonRpcProvider(rpcUrl[el]);
        values.map(async (val) => {
            console.log("GetEvents Started-",el,"-",val);
            const currentBlock = await provider.getBlockNumber();
            const peer = new ethers.Contract(contractAddress[el][val], abi, provider);
            const filter = peer.filters.Deposit();
            let events = [];
            for(let i = startBlock[el]; i < currentBlock; i += 5000) {
                const _startBlock = i;
                const _endBlock = Math.min(currentBlock, i + 4999);
                const _events = await peer.queryFilter(filter, _startBlock, _endBlock);
                events = [...events, ..._events]
            }
            const currentEvents = events
                .sort((a, b) => a.args.leafIndex - b.args.leafIndex)// Sort events in chronological order
                .map((e) => { return { commitment: e.args.commitment, leafIndex: e.args.leafIndex };});
            
            totalEvents[el][val] = currentEvents;

            const leaves = currentEvents.map(e=>e.commitment);
            totalMerkleTrees[el][val] = new MerkleTree(MERKLE_TREE_HEIGHT, leaves);

            console.log("GetEvents Finished-",el,"-",val);
        });
        try {
            await provider.on("block", async(blockNumber) => {
                if(blockNumber != lastBlock[el]) {
                    values.map(async (val) => {
                        const peer = new ethers.Contract(contractAddress[el][val], abi, provider);
                        const filter = peer.filters.Deposit();
                        const _events = await peer.queryFilter(filter, blockNumber-1, blockNumber);

                        if(_events.length > 0) {                        
                            const isExist = totalEvents[el][val].find((event) => event.commitment === _events[0].args.commitment) !== undefined;
                            if(!isExist) {
                                totalEvents[el][val].push({ commitment: _events[0].args.commitment, leafIndex: _events[0].args.leafIndex });
                                totalMerkleTrees[el][val].insert(_events[0].args.commitment);
                                console.log("New Event-",el,"-",val);
                            }
                        }
                    });
                    lastBlock[el] = blockNumber;
                }
            });
        }catch(ex) {

        }
    });
}

getEvents();
