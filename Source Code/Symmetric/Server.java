// File Name Server.java

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.GeneralSecurityException;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;



public class Server extends Thread 
{
	private ServerSocket serverSocket;
   
	public Server(int port) throws IOException 
	{
		serverSocket = new ServerSocket(port);	
		//serverSocket.setSoTimeout(10000);
	}
	
	public void run() 
   	{
	   
		System.out.println("Waiting for client... ");
		
		try 
		{
	   
			TinkConfig.register();
    	   
			//Generating key materials with AES_256 using GF/Counter Mode
	  		KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
		      
			//Write to a file
			String mySecretKeyset = "my_keyset.json";
			
			CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(mySecretKeyset)));
		      
			//Reading the keyset from .json file
			keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(mySecretKeyset)));
			   
			
			//Getting the Primitive from input which uses for encryption
	    	Aead aead = AeadFactory.getPrimitive(keysetHandle);
		   
	    	while(true) 
	    	{
	    		try 
	    		{
              
	    			Socket server = serverSocket.accept();
            
	    			DataInputStream in = new DataInputStream(server.getInputStream());
	    			String input = in.readUTF();
	           
	    			byte[] decryptedText = aead.decrypt(parseHexStr2Byte(input), null);
	    			String output = new String(decryptedText);
	    			
	            	//Output in command line
	            	System.out.println("Cipher text is: " + input);
	            	System.out.println("Plain text is: " + output);
		            
	            	// sent message to client ------------------------------------
	            	OutputStream outToClient = server.getOutputStream();
					DataOutputStream out = new DataOutputStream(outToClient);
	    			Scanner myObj = new Scanner(System.in);
					System.out.println("Enter a message");
					String line = myObj.nextLine();
					//encrypting plaintext
					byte[] cipherText = aead.encrypt(line.getBytes(), null);
					out.writeUTF(byte2hex(cipherText));
					//out.writeUTF(line);
	            	// sent message to client ------------------------------------
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
	    		/*catch (GeneralSecurityException e) 
	    		{
	    			// TODO Auto-generated catch block
				 	e.printStackTrace();
				}*/
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
   
   public static void main(String [] args) 
   {
	   int port = Integer.parseInt(args[0]);
	   try 
	   {
		   Thread t = new Server(port);
		   t.start();
	   } 
	   catch (IOException e) 
	   {
		   e.printStackTrace();
	   }
   }
}
