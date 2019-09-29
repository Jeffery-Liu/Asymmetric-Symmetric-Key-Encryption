//File Name Client.java

import java.net.*; 
import java.io.*;
import java.util.*;

//Base Classes for Tink Crypto Library
import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.config.TinkConfig;
import java.security.GeneralSecurityException;
import com.google.crypto.tink.aead.AeadFactory;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;

public class Client 
{   
	public static void main(String [] args) 
	{
		String serverName = args[0];
		int port = Integer.parseInt(args[1]);
		System.out.println("Connecting to Server");
		System.out.println("Just connected to Server");
      
		try 
		{			
			TinkConfig.register();
		      
			//Reading the keyset from .json file
			String mySecretKeyset = "my_keyset.json";
			
			KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(mySecretKeyset)));
			   
			//Getting the Primitive from input which uses for encryption
	    	Aead aead = AeadFactory.getPrimitive(keysetHandle);
	    	
			while(true)
			{
				try 
				{		
					Socket client = new Socket(serverName, port);
					OutputStream outToServer = client.getOutputStream();					
					DataOutputStream out = new DataOutputStream(outToServer);
				  
					Scanner myObj = new Scanner(System.in);
					System.out.println("Enter a message");
					String line = myObj.nextLine();
				  
					//encrypting plaintext
					byte[] cipherText = aead.encrypt(line.getBytes(), null);
					  
					 //out.writeUTF("Client: Hello");
					out.writeUTF(byte2hex(cipherText));

					out.writeUTF(line);
					
					// get message from server --------------------------------------------
					
	            	// get message from server --------------------------------------------
					DataInputStream in = new DataInputStream(client.getInputStream());
	    			String input = in.readUTF();
	    			// decrypted text
	    			byte[] decryptedText = aead.decrypt(parseHexStr2Byte(input), null);
	    			String output = new String(decryptedText);
	            	//Output in command line
	            	System.out.println("Cipher text is: " + input);
	            	System.out.println("Plain text is: " + output);
					// get message from server --------------------------------------------
		  		}	
		      	catch (IOException | GeneralSecurityException e) 
				{
		        e.printStackTrace();
		      	}
			}
		}
		catch(IOException e) 
		{
		   e.printStackTrace();		   
		} 
		catch (GeneralSecurityException e) 
		{
			// TODO Auto-generated catch block
		 	e.printStackTrace();
		}
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
