import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EncryptDecryptApplication {
    private static final String ALGORITHM = "AES";
    private static final String encryptExtension = ".ENCRYPT.bya";
    private static final int KEY_LENGTH = 256;
    private JPasswordField passwordField;
    private JLabel lblPass;
    private JButton encryptDecryptButton;
    private JButton openFileButton;
    private JTextField openFileTextField;
    private JPanel jPanel;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Encrypt/Decrypt Application");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            EncryptDecryptApplication encryptDecryptApplication = new EncryptDecryptApplication();
            frame.setContentPane(encryptDecryptApplication.jPanel);

            frame.setSize(400, 200);
            frame.setVisible(true);
        });


    }



    public EncryptDecryptApplication() {
        encryptDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    char[] passwordChar = passwordField.getPassword();

                    if (passwordChar.length > 0) {
                        //generate PBKDF2WithHmacSHA512 key using user entered password to encrypt and decrypt
                        Key key = generateKey(Arrays.toString(passwordChar));
                        String password = new String(passwordChar);

                        //for more security remove all spaces
                        password.replace(" ", "");

                        //control if fileTextFiled is end with encrypt extension
                        String filedText = openFileTextField.getText();
                        if (filedText.contains(encryptExtension)){
                            decrypt(key, new File(openFileTextField.getText()));
                        }else {
                            encrypt(key, new File(openFileTextField.getText()));
                        }
                    } else {
                        JOptionPane.showMessageDialog(null, "Please enter the password",
                                "Error", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });


        //open file browser when click on openFileButton
        openFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(null);

                if (result == JFileChooser.APPROVE_OPTION) {
                    String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                    openFileTextField.setText(filePath);
                }

            }
        });
    }


    private static Key generateKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 16byte -> 128bit
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), new byte[16], 65536, KEY_LENGTH);
        //generate SecretKeyFactory using algorithm
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();

        // Create a SecretKeySpec object from the derived key bytes
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }


    public static void encrypt(Key passwordKey, File inputFile) throws Exception {
        try{
            performCrypto(Cipher.ENCRYPT_MODE, passwordKey, inputFile);
            JOptionPane.showMessageDialog(null, "The File Has ENCRYPTED",
                    "ENCRYPTED", JOptionPane.INFORMATION_MESSAGE);
        }catch (Exception e){
            JOptionPane.showMessageDialog(null, "We have a ERROR",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void decrypt(Key passwordKey, File inputFile) throws Exception {
        try{
            performCrypto(Cipher.DECRYPT_MODE, passwordKey, inputFile);
            JOptionPane.showMessageDialog(null, "The File Has DECRYPTED",
                    "DECRYPTED", JOptionPane.INFORMATION_MESSAGE);
        }catch (Exception e){
            JOptionPane.showMessageDialog(null, "We have a ERROR",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static void performCrypto(int cipherMode, Key passwordKey, File inputFile) throws Exception {
        byte[] passwordBytes = passwordKey.getEncoded();
        SecretKey key = new SecretKeySpec(passwordBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(cipherMode, key);

        FileInputStream inputStream = new FileInputStream(inputFile);
        String fileName = inputFile.getName();

        byte[] inputBytes = new byte[inputStream.available()];
        inputStream.read(inputBytes);
        byte[] outputBytes = cipher.doFinal(inputBytes);

        String outputFileName = cipherMode == Cipher.ENCRYPT_MODE ?
                fileName + encryptExtension : fileName.replace(encryptExtension, "");

        FileOutputStream outputStream = new FileOutputStream(outputFileName);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();
    }



}
