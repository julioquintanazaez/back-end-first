from typing import Union, Optional, List
from datetime import date

from pydantic import BaseModel, EmailStr 

class UserUPD(BaseModel):	
	username: str
	email: Union[str, None] = None
	full_name: Union[str, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class UserActivate(BaseModel):	
	disable: Union[bool, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
	
class User(BaseModel):	
	username: str
	email: Union[str, None] = None
	full_name: Union[str, None] = None
	role: Union[str, None] = None
	disable: Union[bool, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class UserInDB(User):
    hashed_password: str
	
class UserPassword(BaseModel):
    hashed_password: str
	
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
	username: Union[str, None] = None
	scopes: List[str] = []
	
	
class Project(BaseModel):
	name : str
	description : str 
	manager : str
	mail_manager : EmailStr 
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class ProjectInDB(Project):
	id : str 
	initial_date : date
	update_date : date
	end_date : date
	is_active : bool 
		
class Labor(BaseModel):
	type : str	
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class LaborInDB(Labor):
	id: str		

#-----------------------------
class PL_MaterialUPD(BaseModel):
	quantity : int
	price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class PL_Material(BaseModel):
	material: str
	type_material: str
	quantity : int
	price : float	
	labor_id : str 
	project_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class PL_MaterialInDB(PL_Material):
	id: str	
	amount : float
	
#-------------------------
class PL_TaskActive(BaseModel):
	is_active: Union[bool, None] = None
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
	
class PL_TaskUPD(BaseModel):
	mechanicals : int
	hour : int
	price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class PL_Task(BaseModel):
	description : str
	mechanicals : int
	hour : int
	price : float
	labor_id : str 
	project_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True		
		
class PL_TaskInDB(PL_Task):
	id: str
	hour_men : int
	is_active : Union[bool, None] = None	
	
#-------------------------

class PL_EquipmentUPD(BaseModel):
	quantity : int
	unit_price : float
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class PL_Equipment(BaseModel):
	equipment: str
	quantity : int
	unit_price : float
	labor_id : str 
	project_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class PL_EquipmentInDB(PL_Equipment):
	id: str
	amount : float	
	

#----------------------------------	
	
	
	
class Category_Material(BaseModel):
	id : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Material(BaseModel):
	name : str
	price : float
	category_id : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class MaterialInDB(Material):
	id : str	

class Task(BaseModel):
	name : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class TaskInDB(Task):
	id : str
		
class Equipment(BaseModel):
	name : str
	unit : str
	unit_price : float
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class EquipmentInDB(Equipment):
	id : str

class Labor_MaterialUPD(BaseModel):
	quantity : int
	material_price : float
	price_plus : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Labor_Material(BaseModel):
	quantity : int
	material_price : float
	price_plus : float	
	labor_id : str 
	material_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class Labor_MaterialInDB(Labor_Material):
	id: str	
	amount : float

class Labor_TaskUPD(BaseModel):
	description : str
	mechanicals : int
	hour : int
	price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Labor_Task(BaseModel):
	description : str
	mechanicals : int
	hour : int
	price : float
	end_date : Union[date, None] = None
	labor_id : str 
	task_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True		
		
class Labor_TaskInDB(Labor_Task):
	id: str
	hour_men : int
	initial_date : Union[date, None] = None	
	update_date : Union[date, None] = None	
	is_active : Union[bool, None] = None
	
class Labor_EquipmentUPD(BaseModel):
	quantity : int
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Labor_Equipment(BaseModel):
	quantity : int
	labor_id : str 
	equipment_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Labor_EquipmentInDB(Labor_Equipment):
	id: str
	amount : float	
	unit_price_lb : float
	
