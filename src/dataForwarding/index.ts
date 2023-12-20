import { FastifyInstance, FastifyServerOptions } from "fastify";
import { agent, DEFAULT_IDENTIFIER_SCHEMA } from "../setup.js";
import { argon2id, argon2Verify, sha256, createSHA256} from "hash-wasm";

import * as jose from 'jose'
import { encode, decode } from '@ipld/dag-json'
import { CID } from 'multiformats'
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import * as ethers  from  "ethers";
const keyto = require('@trust/keyto'); //this is the winner ... but its old and crappy so maybe not that much of a winner. 
import * as didJWT from 'did-jwt'; //NEW WINNER  didJWT.ES256KSigner(didJWT.hexToBytes(debug_parent_privatekey))  
import {Resolver} from 'did-resolver';  //for did-jwt
import dotenv from "dotenv";
//@ts-ignore
import {getResolver} from 'ethr-did-resolver' //TODO remove 
import { getResolver as pkhDidResolver } from "pkh-did-resolver"; 


dotenv.config();



const identifier = await agent.didManagerGetByAlias({
  alias: DEFAULT_IDENTIFIER_SCHEMA,
});






if(false){
let pkhidentifier ;

try {
  pkhidentifier =  await agent.didManagerGetByAlias({
  alias: "pkhidentifier", provider: "did:pkh"
});
  console.log("🚀 ~ file: index.ts:88 ~ pkhidentifier:", pkhidentifier)
} catch (error) {
 // console.log("🚀 ~ file: index.ts:89 ~ Catch:", error)
  
}


if( ! pkhidentifier ){
  pkhidentifier = await agent.didManagerCreate({
    alias: "pkhidentifier",
    provider: "did:pkh",
});
  console.log("🚀 ~ file: index.ts:100 ~ pkhidentifier:", pkhidentifier)
}



let jwkidentifier ;

try {
  jwkidentifier =  await agent.didManagerGetByAlias({
  alias: "jwkidentifier", provider: "did:jwk"
});
  console.log("🚀 ~ file: index.ts:88 ~ jwkidentifier:", jwkidentifier)
} catch (error) {
  //console.log("🚀 ~ file: index.ts:89 ~  Catch:", error)
  
}
if( ! jwkidentifier ){
  jwkidentifier = await agent.didManagerCreate({ 
    alias: "jwkidentifier",
    provider: "did:jwk",
});
  console.log("🚀 ~ file: index.ts:100 ~ jwkidentifier:", jwkidentifier)
}
if(jwkidentifier && jwkidentifier.keys[0].meta){

  const inkey = await agent.keyManagerGet({kid: jwkidentifier.keys[0].kid})
  console.log("🚀 ~ file: index.ts:125 ~ inkey:", inkey)
  const signedjwt = await agent.keyManagerSignJWT({
    kid: inkey.kid,
   // data: new Uint8Array([21, 31]),
   data: "asdasd",
  })
    console.log("🚀 ~ file: index.ts:129 ~ signedjwt:", signedjwt)

    const jwkdoc = await agent.resolveDid({
      didUrl: jwkidentifier.did,
    })
    

    //@ts-ignore
    if( jwkdoc.didDocument?.verificationMethod && jwkdoc.didDocument?.verificationMethod[0]){
    //@ts-ignore
      const resolvedmjwk = {...jwkdoc.didDocument?.verificationMethod[0].publicKeyJwk};
      console.log("🚀 ~ file: index.ts:139 ~ mjwk:", resolvedmjwk)
      /*
      mjwk: {
      alg: 'ES256K',
      crv: 'secp256k1',
      kty: 'EC',
      use: 'sig',
      x: 'wY83GrbakSpRB3aYRRi2kYmj68QAu0SKyeSvuUruAvU',
      y: 'jPqFq5IGHM4DcLmVidUsY0qXIz4PnpdUhtXr-V-lSP0'
    }

    */
    let jwkjose = await jose.importJWK(resolvedmjwk)
    console.log("🚀 ~ file: index.ts:151 ~ jwkjose:", jwkjose)




    try{
      console.log("🚀 ~ file: index.ts:160 ~ signedjwt:", signedjwt)
      let didJWTdecoded = didJWT.decodeJWT(signedjwt)
      console.log("🚀 ~ file: index.ts:160 ~ didJWTdecoded:", didJWTdecoded)
     


    const { payload:payload11, protectedHeader:protectedHeader11 } = await jose.jwtVerify(signedjwt, jwkjose)
    console.log("🚀 ~ file: index.ts:143 ~ protectedHeader11:", protectedHeader11)
    console.log("🚀 ~ file: index.ts:143 ~ payload11:", payload11)
    }
    catch(e){
      console.log("🚀 ~ ~ e:", e)
    } 
  }

}

}




export type TakeDataHeaders = {
  "producer_jwt": string;
  //"body-sha256":string;
};



if(false){ // this works 
const signer = didJWT.ES256KSigner(didJWT.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f')) // this works 

let jwt = await didJWT.createJWT(
  { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' },
  { issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer },
  { alg: 'ES256K' }
)
console.log(jwt)

let didJWTdecoded = didJWT.decodeJWT(jwt)
console.log("🚀 ~ file: index.ts:39 ~ decoded:", didJWTdecoded)




let resolver = new Resolver({...getResolver({infuraProjectId: '7a8c8616ca2449a7b520889743504cbf'})});

let verificationResponse = await didJWT.verifyJWT(jwt, {
  resolver,
  audience: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
})
 console.log("🚀 ~ file: index.ts:49 ~ verificationResponse:", verificationResponse)
}
 
1===1;


/*

Steps 

Build this version with regular node and docker. 

Then build a version with an external DB option.  

If we use express there will be many more years of code for coPilote to auto complete. V1 of Fastify was released 2018 https://fastify.dev/docs/latest/Reference/LTS/ 
ok so lets use express for now . 


0) Start fresh with simple fastify app 
1) Accept data and save it to SQL DB .  (not supabase tho.  Local SQLITE db might be smart so its all in one. 
  ... docker image that has sqlite included is definetly simpler than asking for an additional service. 



*/ 


//const debug_parent_privatekey ="680425c1f7cbb803be68aff2c841f654e3a2373920268231f99c95a954536ab9" // this fails 
const debug_parent_privatekey = process.env['debug_parent_privatekey']? process.env['debug_parent_privatekey'] : "2163b9e4411ad1df8720833b35dcf57ce44556280d9e020de2dc11752798fddd"
console.log("🚀 ~ file: index.ts:30 ~ debug_parent_privatekey:", debug_parent_privatekey)
const debug_parent_wallet =  new ethers.Wallet(debug_parent_privatekey )
const parent_pubkey = debug_parent_wallet.address; 

const keyJwk  = keyto.from(debug_parent_privatekey, 'blk').toJwk('public');
console.log("🚀 ~ file: index.ts:28 ~ keyJwk:", keyJwk)
keyJwk.crv='secp256k1'
const parent_jwk_pubkey = await jose.importJWK(keyJwk);

// Eth keys should be fine for signing JWS and then also JWT 
const my_privatekey ="08196d9ad2196af7d481f25bd47e3a8cef48998db90360da39631d84969451d9"
const my_etherswallet =  new ethers.Wallet(my_privatekey ) //Not sure if i need the 0x   up front or if its optinoal 
const my_pubkey =my_etherswallet.address
const mykeyJwk  = keyto.from(my_privatekey, 'blk').toJwk('private');
mykeyJwk.crv='secp256k1'
const my_jwk_privatekey = await jose.importJWK(mykeyJwk);


const mykeyJwk_pub  = keyto.from(my_privatekey, 'blk').toJwk('public');
mykeyJwk_pub.crv='secp256k1'
const my_jwk_pubkey = await jose.importJWK(mykeyJwk_pub);

const my_endpoint = "localhost:8080"


const didJWTsigner = didJWT.ES256KSigner(didJWT.hexToBytes(debug_parent_privatekey)) 

let didJWTjwt = await didJWT.createJWT(
  { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' },
  { issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer:didJWTsigner },
  { alg: 'ES256K' });
console.log("🚀 ~ file: index.ts:224 ~ jwt:", didJWTjwt)

let didJWTdecoded = didJWT.decodeJWT(didJWTjwt)
console.log("🚀 ~ file: index.ts:39 ~ decoded:", didJWTdecoded)

try{
  const { payload:payload_didjwt, protectedHeader:protectedHeader5_didjwt } = await jose.jwtVerify(didJWTjwt, parent_jwk_pubkey)
  console.log("🚀 ~ file: index.ts:232 ~ protectedHeader5_didjwt:", protectedHeader5_didjwt)
  console.log("🚀 ~ file: index.ts:232 ~ payload_didjwt:", payload_didjwt)
  if( !payload_didjwt.error){
    console.log(">>> JWT VERIFIED !  <<<")
    console.log(">>> JWT VERIFIED !  <<<")
    console.log(">>> JWT VERIFIED !  <<<")
    console.log("\n")
  }
}
catch(e){
  console.log("🚀 ~ file: index.ts:  ~ handler: ~ e:", e)
  console.log("🚀 ~ file: index.ts:237 ~ e:", e)
}


1===1

/*
const keyidentifier = await agent.didManagerCreate({
  alias: "keyidentifier",
  provider: "did:key",
});


const jwkidentifier = await agent.didManagerCreate({
  alias: "jwkidentifier",
  provider: "did:jwk",
});



*/

1==1;


export default async function TakeDataRoutes(
  server: FastifyInstance,
  options: FastifyServerOptions,
) {
  server.post<{ Headers: TakeDataHeaders }>("/dataForwarding", {
    schema: {
      headers: {
        type: "object",
        properties: {
          "producer_jwt": { type: "string" },
        },
        required: ["producer_jwt"],
      },
      // body: {
      //   type: "object",
      //   properties: {
      //     did: {
      //       type: "string",
      //     },
      //     answerHash: {
      //       type: "string",
      //     },
      //     validatorDid: {
      //       type: "string",
      //     },
      //     executionTime: {
      //       type: "number",
      //     },
      //   },
      //   required: ["proofOfWork"],
      // },
    },

    handler: async (request, reply) => {
      const producer_jwt = request.headers["producer_jwt"];
      console.log("🚀 ~ file: index.ts:73 ~ handler: ~ producer_jwt:", producer_jwt)






      /*
        const salt = new Uint8Array(16);
      
        const key = await argon2id({
          password: 'pass',
          salt, // salt is a buffer containing random bytes
          parallelism: 1,
          iterations: 256,
          memorySize: 512, // use 512KB memory
          hashLength: 32, // output size = 32 bytes
          outputType: 'encoded', // return standard encoded string containing parameters needed to verify the key
        });
      
        console.log('Derived key:', key);
      
        const isValid = await argon2Verify({
          password: 'pass',
          hash: key,
        });
        console.log("🚀 ~ file: index.ts:104 ~ run ~ isValid:", isValid)
      
        console.log(isValid ? 'Valid password' : 'Invalid password');

      */




      if(producer_jwt && request.body ){

        console.log("🚀 ~ file: index.ts:79 ~ handler: ~ parent_jwt_pubkey:", JSON.stringify(parent_jwk_pubkey))

        try{
        const { payload:payload5, protectedHeader:protectedHeader5 } = await jose.jwtVerify(producer_jwt, parent_jwk_pubkey)
         
        console.log("🚀 ~ file: index.js:60 ~ payload5:", payload5)
        console.log("🚀 ~ file: index.js:60 ~ protectedHeader5:", protectedHeader5)
        
    
        if( !payload5.error){
        
        const body = JSON.stringify(await request.body);
        console.log("🚀 ~ file: index.ts:93 ~ handler: ~ body:", body)
        const dag_json_endcode=encode(body);
        console.log("🚀 ~ file: index.ts:95 ~ handler: ~ dag_json_endcode:", dag_json_endcode)
        const decodebody=decode(dag_json_endcode);
        console.log("🚀 ~ file: index.ts:97 ~ handler: ~ decodebody:", decodebody)

        const decodebodyHash =  await sha256(decodebody);
        console.log("🚀 ~ file: index.ts:100 ~ handler: ~ decodebodyHash:", decodebodyHash)

        const bodyhashHex =  await sha256(body);
         console.log("🚀 ~ file: index.ts:98 ~ handler: ~ bodyhashHex:", bodyhashHex)
         const dagjsonhashHex =  await sha256(dag_json_endcode);
         console.log("🚀 ~ file: index.ts:100 ~ handler: ~ dagjsonhashHex:", dagjsonhashHex)



        const signed_body_hash = await new jose.SignJWT({ 'urn:recieved:data': true , "data:hash":bodyhashHex, "my_endpoint":my_endpoint})
        .setProtectedHeader({ alg:'ES256K'})  // ES256K  doesn't wokr   ES256K
        .setIssuedAt()
        .setIssuer('urn:example:issuer')
        .setAudience('urn:example:audience')
        .setExpirationTime('30s')
        .sign(my_jwk_privatekey)
        console.log("🚀 ~ file: index.ts:119 ~ handler: ~ signed_body_hash:", signed_body_hash)
 



         
        return reply.status(200).send({"bodyhashHex":bodyhashHex, "ack_jwt":signed_body_hash, "server_Jwk_pub":mykeyJwk_pub, "server_pubkey":my_pubkey});
        }
        }
        catch(e){
          console.log("🚀 ~ file: index.ts:104 ~ handler: ~ e:", e)
          
        }
    
    
        
      }


      return reply.status(401).send("Failed");
 
    },
  });
}
