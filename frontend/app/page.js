"use client"

import { act, useState } from "react";

export default function Home() {

  const [algorithm, setalgorithm] = useState("aes")
  const [action, setaction] = useState("encrypt")
  const [key, setkey] = useState('')
  const [data, setdata] = useState('')
  const [result, setresult] = useState('')
  const [loading, setloading] = useState('false')


  const buildendpoint= ()=>{
    if(algorithm==='sha') return 'v1/hash/sha256'
    return `v1/${action}/${algorithm}`;
  }

  const handlesubmit=async ()=>{
    setloading(true);
    setresult('');
    
    const payload= 
      algorithm==='rsa'
        ?action==='encrypt'
          ?{data,publicKey:key}
          :{data,privateKey:key}
        :algorithm==='sha'
        ?{data}
        :{data,key};
    
    try{
      const response=await fetch(`https://localhost:8080/${buildendpoint()}`,{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify(payload),
      })


      if(!response.ok) throw new Error("request failed");

      const json=await response.json();
      setresult(json.result || json.hash || "no result returned");
    }catch(error){
      setresult(`Error : ${error.message}`);
    }finally{
      setloading("false");
    }
  }
  return (
    <>
    <main className="min-h-screen bg-gray-100 flex justify-center p-6">
      <div className="bg-white shadow-md rounded-lg mt-5 mb-10 items-center p-8 w-full max-w-3/4">
        <h1 className="text-2xl font-bold text-black text-center mb-6">GRPC-REST Crypto-Client</h1>

        <div className="grid grid-cols-2 gap-2 m-5 place-items-center">
          <div> 
            <label className="block pl-1 mb-2  font-bold text-gray-700 text-xl ">Algorithm</label>
            <select className="text-gray-600 p-2 border rounded-md"
            value={algorithm}
            onChange={(e)=>{setalgorithm(e.target.value);
              setkey('');
              setdata('');
              setresult(null);
            }}>
              <option value="aes">Advance Encryption Standard (AES)</option>
              <option value="des">Data Encryption Standard (DES)</option>
              <option value="rsa">Rivest–Shamir–Adleman (RSA)</option>
              <option value="sha">Secure Hash Algorithm (SHA)</option>
            </select>
          </div>

          {algorithm!=="sha" && (
            <div className="mb-4">
              <label className="block font-bold pl-1 text-gray-700 text-xl mb-2">Action</label>
              <select className="text-gray-600 p-2 border rounded-md"
              value={action}
              onChange={(e)=>{setaction(e.target.value);
                if(algorithm==="rsa"){
                  setkey('');
                }
                
                setdata('')
              }}
              >
                <option value="encrypt">Encrypt</option>
                <option value="decrypt">Decrypt</option>
              </select>
            </div>
          )}
        </div>

        {algorithm !=="sha" && (
          <div>
            <label className="text-md text-black">
              {algorithm === "rsa"
              ? action === "encrypt"
                ? 'PublicKey (PEM FORMAT)'
                : 'PrivateKey (PEM FORMAT)'
              : 'Key'
              }
            </label>
            <textarea
              className="w-full p-2 border border-black text-gray-600 rounded-md font-mono"
              rows={algorithm==="rsa"
                ? action==="encrypt"
                  ? 3
                  : 5
                : 2
              }
              value={key}
              onChange={(e)=>setkey(e.target.value)}
            placeholder={
              algorithm==="rsa"
              ? '-----BEGIN PUBLIC KEY-----.......................................-----END PUBLIC KEY-----'
              : 'Enter symmetric key (base64 for AES/DES)'
            }
            />

          </div>
        )}

        <div className="mb-4">
          <label className="text-md text-black" >Data</label>
          <textarea 
          className="w-full p-2 border border-black text-gray-600 rounded-md font-mono"
          rows={2}
          value={data}
          onChange={(e)=>setdata(e.target.value)}
          placeholder="Text to Encrypt/Decrypt/Hash"
          />
        </div>

        <button
        className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
        onClick={handlesubmit}
        disabled={!loading}
        >
          {loading?"Submit":"Processing..."}
        </button>

        {result && (
          <div className="mt-4">
            <label className="block mb-1 font-semibold text-black">Result</label>
            <pre className="bg-gray-200 text-black p-4 rounded text-sm overflow-x-auto whitespace-pre-wrap ">
              {result}
            </pre>
          </div>
        )}
      </div>
    </main>
    </>
  );
}
