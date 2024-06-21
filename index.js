const express = require("express");//express框架
const fs = require("fs");//文件系统模块
const cors = require("cors");//跨域模块
const bodyParser = require("body-parser");
const Web3 = require("web3");
var net = require('net');
const web3 = new Web3(new Web3.providers.IpcProvider('/home/hgxin/mychain/geth.ipc', net));//web3.js

web3.eth.getAccounts(console.log);
const compression = require("compression");//优化组件
const { spawn } = require("child_process");//子进程模块
const keccak256 = require("js-sha3").keccak256;
const EthereumTx = require("ethereumjs-tx").Transaction;
const BigNumber = require("bignumber.js");
const util = require("ethereumjs-util");
var Tx = require('ethereumjs-tx');
const Common = require('ethereumjs-common').default;
const rlp=require('rlp')
//--------------------------------------------------------------
// Express server configuration
//--------------------------------------------------------------
const app = express();
app.use(cors());
app.use(bodyParser.json()); // to support JSON-encoded bodies
app.use(
  bodyParser.urlencoded({
    // to support URL-encoded bodies
    extended: true,
  })
);
app.use(express.static("./public")); //mistake
app.use(compression());
//--------------------------------------------------------------
// Main web pages
//--------------------------------------------------------------
app.get("/", (req, res) => res.sendFile(__dirname + "/default.html"));
//console.time("read data");
fs.readFile('pubKey', function (error, publicKey) {
	if (error) {
   	 console.log('读取pubKey文件失败了')
 	} else {
 	//console.log(publicKey);
  EthreAddr="0x"+util.pubToAddress(publicKey).toString("hex"); 	
 	}	
//console.timeEnd("read data");
//console.log(EthreAddr);

//count= fs.readFileSync('count.txt','utf8');
//web3.eth.getTransactionCount(EthreAddr,"pending",(err,count1)=>{console.log(count1);})

//web3.eth.getTransactionCount(EthreAddr,(err,txcount)=>{
//console.log("count==> ", txcount);})


/*
web3.eth.personal.unlockAccount('0x7fC3A6e089B470bBfa6F60BF7534e928ca9A1463','123456',(err,res)=>{
if(err)
console.log("error");
else{
for(var i=0;i<16;i++){
console.time("trans1");
web3.eth.sendTransaction({
    from: '0x7fC3A6e089B470bBfa6F60BF7534e928ca9A1463',
    to: '0x3eD687b6aE54Cc9BC11631C3932D889E2AaF5f9a',
    value: '1000000000000000'
})
.then(function(receipt){
    console.log(receipt);
});
console.timeEnd("trans1");

}
}
});
*/
/*
const secp256k1 = require('secp256k1');
msgHash1111=Buffer.from('11b0fab66c10ecedd23432ed7330e933181b52437eaa3d746de71f520e3aa97e','hex');
privKey111=Buffer.from('304402201bf4ef3c3496029b1ab1c849bf1855cc16bc526dcc20bdd7b1022053','hex');
s1=secp256k1.ecdsaSign(msgHash1111, privKey111);
console.log(s1.signature.toString("hex"));
*/

/*
var encoded_msg_1=Buffer.from('0x162cd8a09c47521b47fee32b6279acea9b79fa6f','hex');//私钥对应的地址
//c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470//结果

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');


//使用官方算法来跑测试
msgHash1111=Buffer.from('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470','hex');//私钥对应的地址取哈希
privKey111=Buffer.from('1234C2546106BC2C838278698109F32CBA8CDE549C83AB91F2C6346ABB0466E4','hex');//私钥
s1=util.ecsign(msgHash1111, privKey111);//官方算法签名结果
console.log(s1);
*/

/*

msgHash1111=Buffer.from('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470','hex');
let v=27;
//r=Buffer.from('4c63d46f17fa791faa17e26edb3b173abcc6d4b4d349e60a83154811d3c4070b','hex');//test pass in js
//s=Buffer.from('0c55405f75d0fd66b411253ee420118947aecb92534cad860fb9fa60c9b80466','hex');
r=Buffer.from('A35E79B8EE41F4BD5153CA6854C547EA9654E498880026E125BB989D3E4EDD96','hex'); //test pass in TRUSTZONE    
s=Buffer.from('73F68CE388C9EE0E1824C75E97846847DAEC07E84F6C2E2B6319B74157CBC871','hex');


pubKey111 = util.ecrecover(msgHash1111, v, r, s);
let addrBuf = util.pubToAddress(pubKey111);
 let RecoveredEthAddr = util.bufferToHex(addrBuf);
 console.log("diyige ",RecoveredEthAddr);
v = 28;
    pubKey111 = util.ecrecover(util.toBuffer(msgHash1111), v, r, s);
    addrBuf = util.pubToAddress(pubKey111);
    RecoveredEthAddr = util.bufferToHex(addrBuf);
  
  console.log("dierge ",RecoveredEthAddr);
*/

//公钥转地址测试私钥是否正确
/*
publicKey_tz=Buffer.from('1D22DD3B2AA37E03111855E77FAF33C793697A55A471CEEF9683345385D9868B32DB4A483B2BB69036456738359B6F2FA9659F108934AD305ED6AA780903343E','hex');
tz1=util.pubToAddress(publicKey_tz);
let tz_add= util.bufferToHex(tz1);
console.log("gongyao_add ",tz_add);
*/

app.get("/api/getpublickey", (req, res) => {
	
fs.readFile('pubKey', function (error, publicKey) {
	if (error) {
   	 console.log('读取pubKey文件失败了')

 	} else {
 	
 	const EthreAddr="0x"+util.pubToAddress(publicKey).toString("hex"); 
 	res.send(EthreAddr);	
 	}
 	})
});


app.get("/api/tx/firstsign", (req, res) => {
  //First sign : sign the ethreum address of the sender
  	 encoded_msg = EthreAddr;
	 //encoded_msg = '0x7fc3a6e089b470bbfa6f60bf7534e928ca9a1463';//地址目前先直接给出，之后考察是否能够通过公钥得到正确的地址
	 //encoded_msg='0xf974c46d5ba834d3a25cd4dd194afa0c63ebcbcf';//test

	 
	 
	 //console.log("Turn",i+1);
	 //console.time("firstsign");
         msgHash = util.keccak(encoded_msg);// msg to be signed is the generated ethereum address
        // console.timeEnd("firstsign");
	 //msgHash = Buffer.concat([msgHash,msgHash_Temp]);	
	console.log("//Initialize stage")
	console.log("hash_addr====>")			
	console.log(msgHash)			
  	 	
  	/*
 pk=Buffer.from('8228A1F4A81239E1EF7ECB03916AD3711C9D7A2799856236BA8322B735B119F3','hex');
	s1=util.ecsign(msgHash,pk);
	console.log(s1);
*/  //test signature

	//将msgHash存在本地交给sgx签名
	fs.writeFile('msgHash',msgHash,function(error){
	if(error){
	console.log('存储文件失败了')
	}else{
	//console.log('success');
	res.send(msgHash.toString("hex"));
	}
	})
	
	fs.writeFile('msgHash.txt',msgHash.toString("hex"),function(error){
	if(error){
	console.log('存储文件失败了')
	}else{
	//console.log('success');
	}
	})

})

const customCommon = Common.forCustomChain(
  'mainnet',
  {
    name: 'my-network',
    networkId: 1337,
    chainId: 1337,
  },
  'petersburg',
)

app.get("/api/tx/secondsign", (req, res) => {
	var msgHash2=Buffer.from('','hex');

	//Second sign: sign the raw transactions
	fs.readFile('msgHash',function(error,msgHash){
	//console.log("msgHash's Value:",msgHash);
	fs.readFile('firstsign',function(error,firstsign){
	//console.log("firstsign's Value:",firstsign);
  	//console.log("EthreAddr's Value:",EthreAddr);

  	addressSign=rsv(firstsign,msgHash);
	count=84;//注意下面的结构中也要对应修改

  	var _from = EthreAddr;
  	//web3.eth.getTransactionCount(_from,(err,txcount)=>{
    	var rawTx ={
	chainId: 1337,
        nonce: web3.utils.toHex(count), 
        gasPrice: web3.utils.toHex(web3.utils.toWei('12','gwei')),
        gasLimit: web3.utils.toHex(21000),
        to: '0x3ed687b6ae54cc9bc11631c3932d889e2aaf5f9a',
        value:web3.utils.toHex(web3.utils.toWei('1','ether')),
        r: addressSign.r, // using r from the first signature
        s: addressSign.s, // using s from the first signature
        v: addressSign.v+1337*2+8,
	}
 	var tx = new Tx(rawTx,{common: customCommon});
 	msgHash2 = tx.hash(false);

  	
  	fs.writeFile('msgHash2',msgHash2,function(error){});
 	fs.writeFile('msgHash2.txt',msgHash2.toString("hex"),function(error){});
 	console.log("hash_TX====>")			
	console.log(msgHash2)
	res.send(msgHash2.toString("hex"));
})
        })	
  	})

app.get("/api/tx/secondsign2", (req, res) => {
var keythereum = require("keythereum");
web3.eth.net.getId().then((chainId_1)=>{
    //console.log("chainId==>", chainId_1);
	//Second sign: sign the raw transactions
	fs.readFile('msgHash2',function(error,msgHash){
	console.log("msgHash's Value:",msgHash);
	fs.readFile('secondsign',function(error,secondsign){
	//console.log("secondsign's Value:",secondsign);
	//var secondsign2='2aacd27aa5e7188cf1557000838aac39f0ed767594fda4537dff0ce620028e4829161c5391fa739465599973e7a53878f54ce541cca2e233437b0b5e3dc353e3';//success test
	//var secondsign2='490D7DC395254C30E7021F20ACB0EBAD8E3CD8B01297502EAAE8B0B04154BD7C6B6287D2769AEDC16FDC5246CADC5DCF08637DBD4A89EB96BE84D6773C53F424';//测试通过，还未提交此交易，之后截图再用
  	//const secondsign = Buffer.from(secondsign2, "hex");
  	

  	addressSign=rsv(secondsign,msgHash);
  	count=84;

       var _from = EthreAddr;
    	var rawTx={
	chainId: 1337,
        nonce: web3.utils.toHex(count),
        gasPrice: web3.utils.toHex(web3.utils.toWei('12','gwei')),
        gasLimit: web3.utils.toHex(21000),
        to: '0x3ed687b6ae54cc9bc11631c3932d889e2aaf5f9a',
        value:web3.utils.toHex(web3.utils.toWei('1','ether')),
        r: addressSign.r, // using r from the first signature
        s: addressSign.s, // using s from the first signature
        v: addressSign.v+chainId_1*2+8,
	}
	var tx = new Tx(rawTx,{common: customCommon});

	//add=tx.getSenderPublicKey();
	//console.log("PUBLICKEY: ",add);
	var serializedTx = tx.serialize();
  //输出签名后的字符串

 //console.log('0x' + serializedTx.toString('hex'));

web3.eth.sendSignedTransaction(
        '0x'+ serializedTx.toString('hex'),function(error,hash){if(error)console.log("SEND TRANSACTION WRONG");else console.log("RIGNT");}).on('receipt',console.log);

          

	
})      
})
        })
  	})
  	
const rsv = (tempsig,msgHash) => {
  const rs = {
    r: tempsig.slice(0, 32),
    s: tempsig.slice(32, 64),
  };
  console.log("R Value====>");
  console.log(rs.r)
  console.log("S Value====>");
  console.log(rs.s)
  
  s_value = new BigNumber(rs.s.toString("hex"), 16);
  secp256k1N = new BigNumber(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16
    );
    secp256k1halfN = secp256k1N.dividedBy(new BigNumber(2));

  let v = 27;
  let pubKey = util.ecrecover(util.toBuffer(msgHash), v, rs.r, rs.s);
  let addrBuf = util.pubToAddress(pubKey);
  let RecoveredEthAddr = util.bufferToHex(addrBuf);
	
    if (s_value.isLessThan(secp256k1halfN)) {console.log("S_value is satisfied");}
else{
console.log("S_value is wrong");
}	
	
  if (EthreAddr != RecoveredEthAddr) {
    v = 28;
    pubKey = util.ecrecover(util.toBuffer(msgHash), v, rs.r, rs.s);
    addrBuf = util.pubToAddress(pubKey);
    RecoveredEthAddr = util.bufferToHex(addrBuf);
  }
  console.log("LocalEthAddr:",EthreAddr);
  console.log("RecoveredEthAddr:",RecoveredEthAddr);
  console.log("V value->:",v+1337*2+8)
  return { r: rs.r, s: rs.s, v: v };

}


app.get("/api/tx/submit", (req, res) => {
var keythereum = require("keythereum");
console.log("web3-version==> ", Web3.version);
web3.eth.net.getId().then((chainId)=>{
    console.log("chainId==> ", chainId);
});



var _from = '0x7fc3a6e089b470bbfa6f60bf7534e928ca9a1463';
web3.eth.getTransactionCount(_from,(err,txcount)=>{
     var rawTx ={
	chainId: 1337,
        nonce: web3.utils.toHex(txcount),
        gasPrice: web3.utils.toHex(web3.utils.toWei('10','gwei')),
        gasLimit: web3.utils.toHex(21000),
        to: '0x3ed687b6ae54cc9bc11631c3932d889e2aaf5f9a',
        value:web3.utils.toHex(web3.utils.toWei('10','ether')),
}


var tx = new Tx(rawTx);
//var privatekey=Buffer.from('5bd3d9f9b5fc1a116902987398167c5262b8659ce588e641c4bbaf9d13c8fd2d', 'hex');
//定义一个计算私钥的函数
function getPrivateKey(){
  //jsonStr为节点目录下keystore文件的内容
  var jsonStr='{"address":"7fc3a6e089b470bbfa6f60bf7534e928ca9a1463","crypto":{"cipher":"aes-128-ctr","ciphertext":"ab2d6c2c0c7ddcd9f1dd37739b5535983c0789ae6a3a8f01218b3eeb6f62504a","cipherparams":{"iv":"c30a144e36089e4023989ec777d2b809"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"3d49eada5e26f49f87c7917da62d96da525625be8181a8acc06f62c703dee327"},"mac":"85ef8b60b65568e75867061471c953ea9b85345e4f8193850815da6d051fa5c3"},"id":"f37ed694-6a8d-4085-9f47-e0d07e66ed4a","version":3}';
  //转换为json对象
  var keyObject = JSON.parse(jsonStr);
  //利用keythereum计算privatekey（私钥）
  //传入参数为("解锁账户时所需的密码",keyObject)
  var privatekey = keythereum.recover("123456",keyObject);
    
  console.log("the private key is:",privatekey.toString('hex'));
 
  return privatekey;
}
  //获取私钥Privatekey
 privatekey=getPrivateKey();
  //开始签名交易
  tx.sign(privatekey);
  var serializedTx = tx.serialize();

  //输出签名后的字符串
  console.log('0x' + serializedTx.toString('hex'));
web3.eth.sendSignedTransaction(
        '0x'+ serializedTx.toString('hex')).on('receipt',console.log);
});

})

})
//------------------------------------------------------------------------
app.listen(8080, () =>
  console.log("Web app listening at http://localhost:8080")
);

