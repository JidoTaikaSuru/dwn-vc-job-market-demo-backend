import { FastifyInstance, FastifyServerOptions } from "fastify";
import { agent, DEFAULT_IDENTIFIER_SCHEMA } from "../setup.js";
import { argon2id, argon2Verify, sha256, createSHA256} from "hash-wasm";

import * as jose from 'jose'
import { encode, decode } from '@ipld/dag-json'
import { CID } from 'multiformats'
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import * as ethers  from  "ethers";
const keyto = require('@trust/keyto'); //this is the winner

import dotenv from "dotenv";


dotenv.config();


export type TakeDataHeaders = {
  "producer_jwt": string;
  //"body-sha256":string;
};

 



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
