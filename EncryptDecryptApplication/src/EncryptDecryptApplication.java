import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class EncryptDecryptApplication {
    private JPasswordField passwordField;
    private JLabel lblPass;
    private JButton encryptDecryptButton;
    private JButton openFileButton;
    private JTextField openFileTextField;

    public EncryptDecryptApplication() {
        encryptDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try{

                    String password = passwordField.getPassword().toString();
                    //remove spaces for most security
                    password = password.replace(" ", "");
                    if(!(password.isEmpty())){


                    }
                }catch (Exception exception){

                }
            }
        });

    }
    public static void encrypt(String passwordKey, File inputFile) throws Exception {
        //Create encrypt password
        byte[] passwordBytes = passwordKey.getBytes();
        SecretKey key = new SecretKeySpec(passwordBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        //Select encrypt method
        cipher.init(Cipher.ENCRYPT_MODE, key);


        FileInputStream inputStream = new FileInputStream(inputFile);
        String fileName = inputFile.getName();

        //convert file to bytes
        byte[] inputBytes = new byte[inputStream.available()];
        inputStream.read(inputBytes);
        byte[] outputBytes = cipher.doFinal(inputBytes);

        //save encrypt file
        FileOutputStream outputStream = new FileOutputStream(fileName + "ENCRYPT.bya");
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();
    }
}
