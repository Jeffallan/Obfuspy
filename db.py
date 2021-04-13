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
    program_id = Column(Integer, ForeignKey("program.id"))
    program = relationship(Program, backref='program')
    name = Column(String)
    instruction_count = Column(Integer)
    jump_count = Column(Integer)
    blocks = Column(Integer)

class Block(Base):
    __tablename__ = "block"
    id = Column(Integer, primary_key=True)
    function_id = Column(Integer, ForeignKey("function.id"))
    function = relationship(Function, backref='function')
    name = Column(String)
    instruction_count = Column(Integer)

class Instruction(Base):
    __tablename__ = "instruction"
    id = Column(Integer, primary_key=True)
    block_id = Column(Integer, ForeignKey("block.id"))
    block = relationship(Block, backref='block')
    name = Column(String)
    offset = Column(String)
    byte_str = Column(String)
    op = Column(String)

def create_db(name: str):
    engine = create_engine(f"sqlite:///{name}.db")
    if not database_exists(engine.url):
        create_database(engine.url)
        Base.metadata.create_all(engine)
    return engine