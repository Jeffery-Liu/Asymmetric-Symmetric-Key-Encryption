// File Name Server.java

import java.net.*;
import java.io.*;
import java.util.*;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Paths;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Path;


public class ClientRSA  
{
	public static void main(String [] args) throws Exception {

		String serverName = args[0];
		int port = Integer.parseInt(args[1]);
		System.out.println("Connecting to Server");
		System.out.println("Just connected to Server");
		
		//PublicKey pubKey = get("privateKey.txt"); 
		
		/* Read all bytes from the private key file */
		byte[] pri = Files.readAllBytes(Paths.get("privateKey.key"));
		 
		/* Generate private key */
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(pri);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey priKey = kf.generatePrivate(ks);
		
		/* Read all bytes from the public key file */
		byte[] pub = Files.readAllBytes(Paths.get("publicKey.pub"));
		
		/* Generate public key */
		X509EncodedKeySpec ks2 = new X509EncodedKeySpec(pub);
		KeyFactory kf2 = KeyFactory.getInstance("RSA");
		PublicKey pubKey = kf.generatePublic(ks2);
        
        while(true)
        {
        	Socket client = new Socket(serverName, port);
			OutputStream outToServer = client.getOutputStream();					
			DataOutputStream out = new DataOutputStream(outToServer);
		  
			// sent message to server
			Scanner myObj = new Scanner(System.in);
			System.out.println("Enter a message");
			String line = myObj.nextLine();
			
			// encrypt the message
	        byte [] encrypted = encrypt(pubKey, line);     
	        //System.out.println(new String(encrypted));  // <<encrypted message>>
	        out.writeUTF(byte2hex(encrypted));
	        
	        // ----------------------------------------------------------------------------------
	        // receive message from server
	        DataInputStream in = new DataInputStream(client.getInputStream());
 			String input = in.readUTF();
 	
 			// decrypt the message 	            	
 	        byte[] decrypted = decrypt(priKey, parseHexStr2Byte(input));    
         	System.out.println("Cipher text is: " + input);                             
 	        System.out.println("Plain text is: " + new String(decrypted));
	        
        }        
        
	}

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);      
        return keyPairGenerator.genKeyPair();
    }

    public static byte[] encrypt(PublicKey pubKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, (Key) pubKey);  

        return cipher.doFinal(message.getBytes());  
    }
    
    public static byte[] decrypt(PrivateKey priKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        
        return cipher.doFinal(encrypted);
    }
    
    public static String byte2hex(byte buf[]) 
	{
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) 
		{
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) 
			{
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}
	
	public static byte[] parseHexStr2Byte(String hexStr) 
	{
		if (hexStr.length() < 1)
			return null; 
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) 
		{
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
					16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}
}


/* REFERENCES */
// https://www.novixys.com/blog/how-to-generate-rsa-keys-java/#2_Generating_a_Key_Pair
