from typing import Dict, Tuple
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from dataclasses import dataclass
import time
import json
import uuid


def keygen() -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    """ Generate a RSA key pair """

    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key


def generate_signature(message: bytes, private_key: RSA.RsaKey) -> bytes:
    """ Sign a message with a private RSA key """

    hash = hash_message(message)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hash)
    return signature


def verify(message: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    """ Verify a the signature of a message with a public RSA key """

    hash = hash_message(message)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hash, signature)
        return True
    except ValueError:
        return False


def hash_message(message: bytes) -> SHA256.SHA256Hash:
    """ Hash a message """

    hash = SHA256.new(message)
    return hash
    

@dataclass
class Metadata:
    """ Data about the document """

    author_id: str
    author_name: str
    organization: str
    timestamp: float
    location: str
    title: str
    description: str
    edited_from: str
    license: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__)
    

@dataclass
class Author:
    """ A class representing an author """

    name: str
    id: str


class IDProvider:
    """ Generic digital identification provider """

    def __init__(self):
        # author id -> (author, (public key, private key))
        self.authors: Dict[str, Tuple[Author, Tuple[RSA.RsaKey, RSA.RsaKey]]] = {}


    def create_author_id(self) -> str:
        """ Create a unique author id """

        author_id = uuid.uuid4()
        return str(author_id)
    
    
    def register(self, author_name: str) -> Author:
        """ Register a new author with the provider """

        author_id = self.create_author_id()
        private_key, public_key = keygen()
        author = Author(author_name, author_id)

        # In a real-world scenario, store an encrypted version of the private key

        self.authors[author_id] = (author, (public_key, private_key))

        return author
    

    def get_public_key(self, author_id: str) -> RSA.RsaKey:
        """ Get the public key of an author """

        _author, (public_key, _private_key) = self.authors[author_id]
        return public_key
    

    def generate_signature(self, author_id: str, document_hash: bytes, metadata: Metadata) -> bytes:
        """ Generate a signature for a document and its metadata """
        
        # Get the private key of the author
        _author, (_public_key, private_key) = self.authors[author_id]
        # Concatenate document hash and metadata
        blob = document_hash + metadata.to_json().encode()
        # Generate signature with the private key
        signature = generate_signature(blob, private_key)

        return signature


    def verify_document(self, document_hash: bytes, metadata: Metadata, signature: bytes) -> bool:
        """ Verify if a document's signature is valid """

        # Get the author id from the metadata
        author_id = metadata.author_id
        # Get the public key of the author
        public_key = self.get_public_key(author_id)
        # Concatenate document hash and metadata into a blob
        blob = document_hash + metadata.to_json().encode()

        # Verify the signature
        is_valid = verify(blob, signature, public_key)
        return is_valid
    

    @staticmethod
    def hash_document(document: bytes) -> bytes:
        """ Hash a document """

        hash = SHA256.new(document)
        return hash.digest()


if __name__ == '__main__':
    
    provider = IDProvider()

    # Author creates an account with the provider
    author_name = 'Alice'
    author = provider.register(author_name)

    # Author creates a document
    document = b'Lorem ipsum dolor sit amet'

    # Metadata of the document
    # This would be generated through an interface on the provider's website
    metadata = Metadata(
        author_id=author.id,
        author_name=author.name,
        organization='My Organization',
        timestamp=time.time(),
        location='Milan, Italy',
        title='My Book',
        description='This book is about ...',
        edited_from='',
        license='MIT'
    )

    # The document is hashed
    document_hash = provider.hash_document(document)

    # Author signs the document
    signature = provider.generate_signature(author.id, document_hash, metadata)
    print('Signature: ', signature.hex())

    # The metadata and the signature are either included in the document or pulished in a separate file


    # Someone else verifies the signature

    # the metadata is found in the published document
    # the signature is found in the published document

    # Realistically, you would extract the signature and metadata from the public document for verification
    # This would be implemented according to the specific file format of the document

    document = b'Lorem ipsum dolor sit amet'

    # Verify the signature
    document_hash = provider.hash_document(document)
    is_valid = provider.verify_document(document_hash, metadata, signature)
    print('Signature is valid' if is_valid else 'Signature is not valid')


    # Try to verify an altered document
    altered_document = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit'
    document_hash = provider.hash_document(altered_document)
    is_valid = provider.verify_document(document_hash, metadata, signature)
    print('Signature is valid' if is_valid else 'Signature is not valid')


    # Try to verify a document with altered metadata (timestamp, since this is created later)
    altered_metadata = Metadata(
        author_id=author.id,
        author_name=author.name,
        organization='My Organization',
        timestamp=time.time(),
        location='Milan, Italy',
        title='My Book',
        description='This book is about ...',
        edited_from='',
        license='MIT'
    )

    document_hash = provider.hash_document(document)
    is_valid = provider.verify_document(document_hash, altered_metadata, signature)
    print('Signature is valid' if is_valid else 'Signature is not valid')

