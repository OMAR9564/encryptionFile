import javax.crypto.Cipher;
import javax.crypto.SecretKey;
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

public class EncryptDecryptApplication {
    private static final String ALGORITHM = "AES";
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
                try{

                    char[] passwordChar = passwordField.getPassword();
                    //remove spaces for most security

                    if((passwordChar.length > 0)){
                        Key key = generateKey();
                        System.out.println(key);
                        String password = new String(passwordChar);
                        password.replace(" ", "");
                        encrypt(password, new File(openFileTextField.getText()));

                    }
                    else{
                        JOptionPane.showMessageDialog(null, "Please enter the password",
                                "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }catch (Exception exception){
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
    private static Key generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a random key of the specified length
        byte[] keyBytes = new byte[KEY_LENGTH / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Create a SecretKeySpec object from the key bytes
        return new SecretKeySpec(keyBytes, ALGORITHM);
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
