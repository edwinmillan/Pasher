import pytest
import pasher


@pytest.mark.parametrize('length', [8, 16, 24])
def test_gen_salt(length):
    salt = pasher.gen_salt(length)
    assert len(salt) == length
    assert isinstance(salt, bytes)


@pytest.mark.parametrize('password', ['Password1', 'TOPSECRET', 'Dj$b23PX!132!'])
@pytest.mark.parametrize('salt', ['Vo3JkLmv4RXJLgYm', None, '87KFwmcXHhFiKxgP'])
def test_generate_pw_hash_with_salt(password, salt):
    pw_hash = pasher.generate_pw_hash(password, salt)
    components = pw_hash.split('$')
    assert isinstance(pw_hash, str)
    assert len(components) == 5
    if salt:
        assert components[2] == salt


@pytest.mark.parametrize('password', ['Password1', 'TOPSECRET', 'Dj$b23PX!132!'])
def test_validate_pw_hash(password):
    wrong_password = password + '_'
    pw_hash = pasher.generate_pw_hash(password)
    true_validation = pasher.validate_pw_hash(pw_hash, password)
    false_validation = pasher.validate_pw_hash(pw_hash, wrong_password)
    assert true_validation is True
    assert false_validation is False
