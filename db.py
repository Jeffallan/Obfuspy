from sqlalchemy import Column, ForeignKey, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database


Base = declarative_base()

class Program(Base):
    __tablename__ = "program"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    block_setting = Column(Integer)
    average_blocks = Column(Integer)
    entropy = Column(Float)
    raw_hex = Column(String)
    size = Column(Float)

class Function(Base):
    __tablename__ = "function"
    id = Column(Integer, primary_key=True)
    program = relationship(Program)
    name = Column(String)
    instruction_count = Column(Integer)
    jump_count = Column(Integer)
    blocks = Column(Integer)

class Block(Base):
    __tablename__ = "block"
    id = Column(Integer, primary_key=True)
    function = relationship(Function)
    name = Column(String)
    instruction_count = Column(Integer)

class Instruction(Base):
    __tablename__ = "instruction"
    id = Column(Integer, primary_key=True)
    block = relationship(Block)
    name = Column(String)
    offset = Column(String)
    byte_str = Column(String)
    op = Column(String)

def create_db(name: str):
    engine = create_engine(f"sqlite:///{name}.db")
    if not database_exists(engine.url):
        create_database(engine.url)
        Base.metadata.create_all(engine)