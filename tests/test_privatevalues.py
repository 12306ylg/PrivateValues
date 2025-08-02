import unittest
import os
import json
from unittest.mock import patch
from privatevalues import PrivateValues

class TestPrivateValues(unittest.TestCase):

    def setUp(self):
        self.test_file = ".test_privatevalues"
        self.sub_package_file = f"{self.test_file}_db"
        self.encrypted_keys_file = ".test_privatevalues_encrypted"
        # Clean up any old test files before running a test
        for f in [self.test_file, self.sub_package_file, self.encrypted_keys_file]:
            if os.path.exists(f):
                os.remove(f)

    def tearDown(self):
        for f in [self.test_file, self.sub_package_file, self.encrypted_keys_file]:
            if os.path.exists(f):
                os.remove(f)

    @patch('privatevalues.core.getpass')
    def test_init_and_set_get(self, mock_getpass):
        mock_getpass.return_value = 'testpassword'
        pv = PrivateValues(path=self.test_file)
        pv.set("my_secret", "my_value")
        self.assertEqual(pv.get("my_secret"), "my_value")
        mock_getpass.assert_called_once_with("Enter new password: ")

    @patch('privatevalues.core.getpass')
    def test_load_and_get(self, mock_getpass):
        # First, create and set a secret
        mock_getpass.return_value = 'testpassword'
        pv_set = PrivateValues(path=self.test_file)
        pv_set.set("my_secret", "my_value")
        mock_getpass.assert_called_once_with("Enter new password: ")

        # Now, load it and get the secret
        mock_getpass.reset_mock()
        mock_getpass.return_value = 'testpassword'
        pv_get = PrivateValues(path=self.test_file)
        self.assertEqual(pv_get.get("my_secret"), "my_value")
        mock_getpass.assert_called_once_with("Enter password: ")


    @patch('privatevalues.core.getpass')
    def test_sub_package(self, mock_getpass):
        mock_getpass.return_value = 'testpassword'
        pv = PrivateValues(path=self.test_file) # Main package

        mock_getpass.reset_mock()
        mock_getpass.return_value = 'subpassword'
        db_secrets = pv.sub_package("db") # Sub package
        db_secrets.set("db_password", "supersecret")
        self.assertEqual(db_secrets.get("db_password"), "supersecret")
        mock_getpass.assert_called_once_with("Enter new password: ")


    def test_encryption(self):
        with patch('privatevalues.core.getpass', return_value='testpassword'):
            pv = PrivateValues(path=self.test_file)
            pv.set("my_secret", "my_value")

        with open(self.test_file, 'r') as f:
            config = json.load(f)
            encrypted_value = config['secrets']['my_secret']
            self.assertNotEqual(encrypted_value, "my_value")

    @patch('privatevalues.core.getpass')
    def test_password_not_required_if_provided(self, mock_getpass):
        pv = PrivateValues(path=self.test_file, password='testpassword')
        pv.set("my_secret", "my_value")
        self.assertEqual(pv.get("my_secret"), "my_value")
        # getpass should not have been called
        mock_getpass.assert_not_called()

    def test_encrypted_keys(self):
        with patch('privatevalues.core.getpass', return_value='testpassword'):
            pv = PrivateValues(path=self.encrypted_keys_file, encrypt_keys=True)
            pv.set("my_secret_key", "my_secret_value")
            self.assertEqual(pv.get("my_secret_key"), "my_secret_value")

        with open(self.encrypted_keys_file, 'r') as f:
            config = json.load(f)
            self.assertTrue(config['encrypt_keys'])
            # The key should be encrypted, so it won't be 'my_secret_key'
            self.assertNotIn("my_secret_key", config['secrets'])

        # Test listing keys
        with patch('privatevalues.core.getpass', return_value='testpassword'):
            pv_load = PrivateValues(path=self.encrypted_keys_file)
            self.assertIn("my_secret_key", pv_load.get_all_keys())

    if __name__ == '__main__':
    unittest.main()
