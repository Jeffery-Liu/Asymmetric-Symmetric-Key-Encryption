// File Name Server.java

import java.net.*;
import java.io.*;
import java.util.*;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class ServerRSA  extends Thread
{
	private static ServerSocket serverSocket;
   
	public ServerRSA(int port) throws IOException 
	{
		serverSocket = new ServerSocket(port);	
		//serverSocket.setSoTimeout(10000);
	}
	
	public static void main(String [] args) throws Exception {
        // generate public and private keys
        KeyPair keyPair = buildKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey priKey = keyPair.getPrivate();
        
        //byte[] publicK = pubKey.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("publicKey.pub");
        keyfos.write(pubKey.getEncoded());
        keyfos.close();

        //byte[] privateK = priKey.getEncoded();
        FileOutputStream keyfos2 = new FileOutputStream("privateKey.key");
        keyfos2.write(priKey.getEncoded());
        keyfos2.close();
        // encryted the message
        //byte [] signed = encrypt(pubKey, "This is a secret message");
        //System.out.println(new String(signed));  // <<signed message>>
        int port = Integer.parseInt(args[0]);
        try 
 	   	{
        	Thread t = new ServerRSA(port);
 		   	t.start();
 			System.out.println("Waiting for client... ");

 		   	while(true) 
 	    	{
 	    		try 
 	    		{          
 	    			Socket server = serverSocket.accept();
 	        
 	    			// receive message from client
 	    			DataInputStream in = new DataInputStream(server.getInputStream());
 	    			String input = in.readUTF();
 	    	
 	    			// decrypted the message 	            	
 	    	        byte[] decrypted = decrypt(priKey, parseHexStr2Byte(input));    
 	            	System.out.println("Cipher text is: " + input);                             
 	    	        System.out.println("Plain text is: " + new String(decrypted));

 	    	        // ----------------------------------------------------------------------------------
 	            	// sent message to client 
 	    	        OutputStream outToServer = server.getOutputStream();
 	    	        DataOutputStream out = new DataOutputStream(outToServer);
 	    	        
 	    	        Scanner myObj = new Scanner(System.in);
	 	  			System.out.println("Enter a message");
	 	  			String line = myObj.nextLine();
	 	  			
	 	  			// encrypt the message
	 	  	        byte [] encrypted = encrypt(pubKey, line);     
	 	  	        //System.out.println(new String(encrypted));  // <<encrypted message>>
	 	  	        out.writeUTF(byte2hex(encrypted));	
	 	  	        // sent message to client 
 		   		} 
 	    		catch (SocketTimeoutException s) 
 	    		{
 	    			System.out.println("Socket timed out!");
 		 			System.out.println("Connection ended!");	
 		 		}
 	    		catch (IOException e) 
 	    		{
 	    			e.printStackTrace();				   
 				} 
 	    		
 	    	}
 	   	} 
 	   	catch (IOException e) 
 	   	{
 	   		e.printStackTrace();
 	   	}
        
        System.out.println("Waiting for client... ");	
	
	}

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);      
        return keyPairGenerator.genKeyPair();
    }

    public static byte[] encrypt(PublicKey pubKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);  

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
