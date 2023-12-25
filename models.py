from database import Base
import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Float, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from fastapi_utils.guid_type import GUID, GUID_DEFAULT_SQLITE

from uuid import UUID, uuid4    


actual_date = datetime.datetime.now()

"""
Main tables required for our bussiness model
	Project:
	Labor:
	Task:
	Equipment:
	Material:	
	Some category tables required for searching porpouses
		Material_Category:
		Labor_Category:
	Association tables:
		Labor_Task:
		Labor_Equipment:
		Labor_Material:
"""

class Project(Base):  #One-to-Many with Labor
	__tablename__ = "project"
	#Main data
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	name = Column(String(50), unique=True, nullable=False, index=True)
	description = Column(String(100), nullable=True, default=None, index=True)
	initial_date = Column(DateTime, nullable=False, server_default=func.now())
	update_date = Column(DateTime, onupdate=func.now()) 
	end_date = Column(DateTime)
	manager = Column(String(50), nullable=False, index=True)
	mail_manager = Column(String(50), nullable=True)
	is_active = Column(Boolean, nullable=True, default=True)	
	
	l_material = relationship("Labor", secondary="pl_material", back_populates='p_material') #Reference field that points to Material table (in labors)
	l_task = relationship("Labor", secondary="pl_task", back_populates='p_task') #Reference field that points to Material table (in labors)
	l_equipments = relationship("Labor", secondary="pl_equipment", back_populates='p_equipment') #Reference field that points to Material table (in labors)
	
class Labor(Base): #Many-to-One with Project
	__tablename__ = "labor"	
	#Main data
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	type = Column(String(100), unique=True, nullable=False, index=True)		
	
	p_material = relationship("Project", secondary="pl_material", back_populates='l_material') #Reference field that points to Material table (in labors)
	p_task = relationship("Project", secondary="pl_task", back_populates='l_task') #Reference field that points to Material table (in labors)
	p_equipment = relationship("Project", secondary="pl_equipment", back_populates='l_equipments') #Reference field that points to Material table (in labors)
	

class User(Base):
	__tablename__ = "user"
	
	username = Column(String(30), primary_key=True, unique=True, index=True) 
	full_name = Column(String(50), nullable=True, index=True) 
	email = Column(String(30), nullable=False, index=True) 
	role = Column(String(15), nullable=False, index=True) #Scopes
	disable = Column(Boolean, nullable=True, default=False)	
	hashed_password = Column(String(100), nullable=True, default=True)	

	
class PL_Material(Base):  #Associetion table between Labor-Material
	__tablename__ = 'pl_material'
	
	#Main data
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	material = Column(String(100), nullable=True, default=None, index=True) 
	type_material = Column(String(100), nullable=True, default=None, index=True) 
	quantity = Column(Integer, nullable=True, default=1)
	price = Column(Float, nullable=True, default=1.0) #es el mismo que el del material
	amount = Column(Float, nullable=True, default=1.0)	
	#Relation association Many-to-Many
	labor_id = Column(GUID, ForeignKey('labor.id'), primary_key=True)   #ForeignKey that point to parent table
	project_id = Column(GUID, ForeignKey('project.id'), primary_key=True)  #ForeignKey that point to parent table
	
class PL_Task(Base):
	__tablename__ = "pl_task"

	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	description = Column(String(100), nullable=True, default=None, index=True) 
	mechanicals = Column(Integer, nullable=True, default=1)
	hour = Column(Integer, nullable=True, default=1)
	hour_men = Column(Integer, nullable=True, default=1)
	price = Column(Float, nullable=True, default=1.0)
	is_active = Column(Boolean, nullable=True, default=True)
	#Relation association Many-to-Many
	labor_id = Column(GUID, ForeignKey('labor.id'), primary_key=True)   #ForeignKey that point to parent table
	project_id = Column(GUID, ForeignKey('project.id'), primary_key=True)  #ForeignKey that point to parent table
	
class PL_Equipment(Base):
	__tablename__ = "pl_equipment"

	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	equipment = Column(String(100), nullable=True, default=None, index=True) 
	quantity = Column(Integer, nullable=True, default=1)
	unit_price = Column(Float, nullable=True, default=1.0)
	amount = Column(Float, nullable=True, default=1.0)
	#Relation association Many-to-Many
	labor_id = Column(GUID, ForeignKey('labor.id'), primary_key=True)   #ForeignKey that point to parent table
	project_id = Column(GUID, ForeignKey('project.id'), primary_key=True)  #ForeignKey that point to parent table
