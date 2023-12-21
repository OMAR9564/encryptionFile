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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EncryptDecryptApplication {
    private static final String ALGORITHM = "AES";

    private static final String encryptExtansion = "ENCRYPT.bya";

    private static final int KEY_LENGTH = 256;
    private JPasswordField passwordField;
    private JLabel lblPass;
    private JButton encryptDecryptButton;
    private JButton openFileButton;
    private JTextField openFileTextField;
    private JPanel jPanel;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Encrypt/Decrypt Uygulaması");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            EncryptDecryptApplication encryptDecryptApplication = new EncryptDecryptApplication();
            frame.setContentPane(encryptDecryptApplication.jPanel);

            // Pencere boyutunu ayarla ve görünür yap
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
                        Key key = generateKey(Arrays.toString(passwordChar));
                        String password = new String(passwordChar);
                        password.replace(" ", "");

                        String filedText = openFileTextField.getText();
                        if (filedText.contains(encryptExtansion)){
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
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();

        // Create a SecretKeySpec object from the derived key bytes
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }


    public static void encrypt(Key passwordKey, File inputFile) throws Exception {
        performCrypto(Cipher.ENCRYPT_MODE, passwordKey, inputFile);
    }

    public static void decrypt(Key passwordKey, File inputFile) throws Exception {
        performCrypto(Cipher.DECRYPT_MODE, passwordKey, inputFile);
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
                fileName + encryptExtansion : fileName.replace(encryptExtansion, "");

        FileOutputStream outputStream = new FileOutputStream(outputFileName);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();
    }



}
