from fastapi import Depends, FastAPI, HTTPException, status, Response, Security, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from functools import lru_cache
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.sql import func
from sqlalchemy import desc, asc
from uuid import uuid4
from pathlib import Path
from typing import Union
from datetime import datetime, timedelta
#---Imported for JWT example-----------
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
from typing_extensions import Annotated
import models
import schemas
from database import SessionLocal, engine
import init_db
import config

#-------FAKE DB------------------------
#User: julio:admin987*!!+  / sherlock: backer356 / marco:marco123
#-------------------------------------
models.Base.metadata.create_all(bind=engine)

#Create resources for JWT flow
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
	tokenUrl="token",
	scopes={"admin": "Add, edit and delete information.", "manager": "Create and read information.", "user": "Read information."}
)
#----------------------
#Create our main app
app = FastAPI()

#----SETUP MIDDLEWARES--------------------

# Allow these origins to access the API
"""
"https://tools.slingacademy.com",
"https://www.slingacademy.com",
"http://localhost.tiangolo.com",
"https://localhost.tiangolo.com",	
"""
origins = [	
	"https://app-project-jczo.onrender.com",
	"http://app-project-jczo.onrender.com",	
	"http://localhost",
	"http://localhost:8080",
	"https://localhost:8080",
	"http://localhost:5000",
	"https://localhost:5000",
	"http://localhost:3000",
	"https://localhost:3000",
	"http://localhost:8000",
	"https://localhost:8000",
]

# Allow these methods to be used
methods = ["GET", "POST", "PUT", "DELETE"]

# Only these headers are allowed
headers = ["Content-Type", "Authorization"]

app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=methods,
	allow_headers=headers,
	expose_headers=["*"]
)

ALGORITHM = config.ALGORITHM	
SECRET_KEY = config.SECRET_KEY
APP_NAME = config.APP_NAME
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES

# Dependency
def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


#------CODE FOR THE JWT EXAMPLE----------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
	db_user = db.query(models.User).filter(models.User.username == username).first()	
	if db_user is not None:
		return db_user 

#This function is used by "login_for_access_token"
def authenticate_user(username: str, password: str,  db: Session = Depends(get_db)):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password): #secret
        return False
    return user
	
#This function is used by "login_for_access_token"
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=5)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
	
#This function is used by "get currecnt active user" dependency security authentication
async def get_current_user(
			security_scopes: SecurityScopes, 
			token: Annotated[str, Depends(oauth2_scheme)],
			db: Session = Depends(get_db)):
	if security_scopes.scopes:
		authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
	else:
		authenticate_value = "Bearer"
		
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception			
		token_scopes = payload.get("scopes", [])
		token_data = schemas.TokenData(scopes=token_scopes, username=username)
		
	except (JWTError, ValidationError):
		raise credentials_exception
			
		token_data = schemas.TokenData(username=username)
	except JWTError:
		raise credentials_exception
		
	user = get_user(db, username=token_data.username)
	if user is None:
		raise credentials_exception
		
	for user_scope in token_data.scopes:
		if user_scope not in security_scopes.scopes:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Not enough permissions",
				headers={"WWW-Authenticate": authenticate_value},
			)
			
	return user
	
async def get_current_active_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["admin", "manager", "user"])]):
	if current_user.disable:
		print({"USER AUTENTICATED" : current_user.disable})
		print({"USER ROLES" : current_user.role})
		raise HTTPException(status_code=400, detail="Inactive user")
	return current_user

#------------------------------------
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
	user = authenticate_user(form_data.username, form_data.password, db)
	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		)
	access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
	print(form_data.scopes)
	print(user.role)
	access_token = create_access_token(
		data={"sub": user.username, "scopes": [user.role]},   #form_data.scopes
		expires_delta=access_token_expires
	)
	return {"access_token": access_token, "token_type": "Bearer"}
	
@app.get("/")
def index():
	return {"Application": "Hello from developers"}
	
@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin", "manager", "user"])]):
    return current_user
	
#########################
###   USERS ADMIN  ######
#########################
@app.post("/create_user/", status_code=status.HTTP_201_CREATED)  
def create_user(user: schemas.UserInDB, db: Session = Depends(get_db)):
	if db.query(models.User).filter(models.User.username == user.username).first() :
		raise HTTPException( 
			status_code=400,
			detail="The user with this email already exists in the system",
		)	
	db_user = models.User(
		username=user.username, 
		full_name=user.full_name,
		email=user.email,
		role=user.role,
		disable=user.disable,
		hashed_password=pwd_context.hash(user.hashed_password)
	)
	db.add(db_user)
	db.commit()
	db.refresh(db_user)	
	return {f"User: {db_user.username}": "Succesfully created"}
	
@app.get("/read_users/", status_code=status.HTTP_201_CREATED)    #current_user: Annotated[schemas.User, Security(get_current_user, scopes=["admin"])]
def read_users(
		skip: int = 0, limit: int = 100,
		db: Session = Depends(get_db)
	):    	
	db_users = db.query(models.User).offset(skip).limit(limit).all()    
	return db_users

@app.put("/update_user/{username}", status_code=status.HTTP_201_CREATED) 
def update_user(username: str, new_user: schemas.UserUPD, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.username=new_user.username
	db_user.full_name=new_user.full_name
	db_user.email=new_user.email		
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.put("/activate_user/{username}", status_code=status.HTTP_201_CREATED) 
def activate_user(username: str, new_user: schemas.UserActivate, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.disable=new_user.disable		
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.delete("/delete_user/{username}", status_code=status.HTTP_201_CREATED) 
def delete_user(username: str, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db.delete(db_user)	
	db.commit()
	return {"Deleted": "Delete User Successfuly"}
	
@app.get("/read_user_by_username/{username}", status_code=status.HTTP_201_CREATED) 
def delete_user(username: str, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	return db_user
	
@app.put("/reset_password/{username}", status_code=status.HTTP_201_CREATED) 
def reset_password(username: str, password: schemas.UserPassword, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db_user.hashed_password=pwd_context.hash(password.hashed_password)
	db.commit()
	db.refresh(db_user)	
	return {"Result": "Password Updated Successfuly"}
		
#######################
#CRUD for PROJECTS here
#######################

@app.post("/create_project/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
def create_project(project: schemas.Project, db: Session = Depends(get_db)):	
	try:
		db_project = db.query(models.Project).filter(models.Project.project_name == project.project_name).first()
		if db_project is None:
			db_project = models.Project(
				project_name=project.project_name, 
				desc_proj=project.desc_proj,			
				manager=project.manager,
				mail_manager=project.mail_manager,
				inidate_proj=func.now(),
				upddate_proj = func.now(),
				latitud=0,
				longitud=0,
				is_active=True, 
			)
			db.add(db_project)
			db.commit()
			db.refresh(db_project)	
			return db_project
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating project")

@app.get("/read_projects/", status_code=status.HTTP_201_CREATED)
def read_projects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	projects = db.query(models.Project).offset(skip).limit(limit).all()    
	return projects
	
@app.put("/update_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def update_project(project_id: str, project: schemas.Project, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")
	db_project.project_name = project.project_name
	db_project.desc_proj = project.desc_proj
	db_project.manager = project.manager
	db_project.mail_manager = project.mail_manager
	db_project.upddate_proj = func.now()
	db.commit()
	db.refresh(db_project)	
	return db_project

@app.delete("/delete_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_project(project_id: str, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")	
	db.delete(db_project)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#####################
#CRUD for LABORS here
#####################

@app.post("/create_labor/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
def create_labor(labor: schemas.Labor, db: Session = Depends(get_db)):		
	try:	
		labors_in_db = db.query(
							models.Project.project_name,
							models.Project.id,
							models.Labor.type,
							models.Labor.id
							).join(models.Labor, models.Project.id == models.Labor.project_id
						).filter_by(type = labor.type
						).filter_by(project_id = labor.project_id
						).all()	
		if 	len(labors_in_db) == 0:		
			db_labor = models.Labor(
				type=labor.type,	
				desc_labor=labor.desc_labor,
				inidate_labor=func.now(),
				upddate_labor=func.now(),
				project_id=labor.project_id, 
			)			
			db_parent_project = db.query(models.Project).filter(models.Project.id == labor.project_id).first()
			db_parent_project.labors.append(db_labor)	
			db.add(db_labor)   	
			db.commit()
			db.refresh(db_labor)			
			return db_labor
		else:
			raise HTTPException(status_code=500, detail="Labor already exists in selected project")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating labor")
		
@app.get("/read_labors/", status_code=status.HTTP_201_CREATED)  
def read_labors(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_labors = db.query(
					models.Labor.id,
					models.Labor.type,
					models.Labor.desc_labor,
					models.Labor.inidate_labor,
					models.Labor.enddate_labor,
					models.Labor.is_active,
					models.Project.project_name,
					(models.Project.id).label('project_labor'),
				).join(models.Labor, models.Project.id == models.Labor.project_id
				).all()	
	return db_labors
	
@app.get("/read_labors_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
def read_labors_by_project_id(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_labors = db.query(
					models.Labor.id,
					models.Labor.type,
					models.Labor.desc_labor,
					models.Labor.inidate_labor,
					models.Labor.enddate_labor,
					models.Labor.is_active,
					models.Project.project_name,
					(models.Project.id).label('project_labor'),
				).join(models.Labor, models.Project.id == models.Labor.project_id
				).filter_by(project_id = project_id
				).all()	
	return db_labors
	
@app.put("/update_labor/{labor_id}", status_code=status.HTTP_201_CREATED) 
def update_labor(labor_id: str, upd_labor: schemas.LaborUPD, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor category not found")
	db_labor.desc_labor=upd_labor.desc_labor
	db_labor.upddate_labor=func.now()
	db.commit()
	db.refresh(db_labor)	
	return db_labor
	
@app.put("/activate_labor/{id}", status_code=status.HTTP_201_CREATED) 
def activate_labor(id: str, labor: schemas.LaborActive, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")
	db_labor.is_active=labor.is_active;		
	db.commit()
	db.refresh(db_labor)	
	return {"Response": "Labor successfully changed its status"}	

@app.delete("/delete_labor/{labor_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_labor(labor_id: str, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")	
	db.delete(db_labor)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#########################	
#------TASK-------------
#########################

@app.post("/create_task/", status_code=status.HTTP_201_CREATED) 
def create_task(task: schemas.Task, db: Session = Depends(get_db)):		
	try:	
		tasks_in_db = db.query(
							models.Labor.type,
							models.Task.id,
							models.Task.description,							
							(models.Labor.id).label('labor_parent')
							).join(models.Task, models.Labor.id == models.Task.labor_task_id
						).filter_by(description = task.description
						).filter_by(labor_task_id = task.labor_task_id
						).all()	
		if 	len(tasks_in_db) == 0:		
			db_task = models.Task(
				description=task.description,	
				mechanicals=task.mechanicals,
				hour=task.hour,  
				task_price=task.task_price,
				hour_men=(task.hour * task.mechanicals),
				inidate_task=func.now(),
				upddate_task=func.now(),
				is_active=True,
				labor_task_id=task.labor_task_id,
			)			
			db_parent_labor = db.query(models.Labor).filter(models.Labor.id == task.labor_task_id).first()
			db_parent_labor.tasks.append(db_task)	
			db.add(db_task)   	
			db.commit()
			db.refresh(db_task)			
			return db_task
		else:
			raise HTTPException(status_code=500, detail="Task already exists in selected Labor")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating task")	

	
@app.get("/read_tasks/", status_code=status.HTTP_201_CREATED)  
def read_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_tasks = db.query(
					models.Task.id,
					models.Task.description,
					models.Task.mechanicals,					
					models.Task.hour,
					models.Task.hour_men,
					models.Task.task_price,
					models.Task.inidate_task,
					models.Task.upddate_task,
					models.Task.enddate_task,
					models.Task.is_active,
					models.Labor.type,
					(models.Labor.id).label('labor_task'),
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).all()	
	
	return db_tasks
	
@app.get("/read_tasks_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
def read_tasks_by_labor_id(labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_tasks = db.query(
					models.Task.id,
					models.Task.description,
					models.Task.mechanicals,
					models.Task.hour,					
					models.Task.inidate_task,
					models.Task.upddate_task,
					models.Task.enddate_task,
					models.Task.is_active,
					models.Task.hour_men,
					models.Task.task_price,
					models.Labor.type,
					(models.Labor.id).label('labor_task'),
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).filter_by(labor_task_id = labor_id
				).all()	
	return db_tasks
	
@app.put("/activate_task/{id}", status_code=status.HTTP_201_CREATED) 
def activate_task(id: str, task: schemas.TaskActive, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_task.is_active=task.is_active;		
	db.commit()
	db.refresh(db_task)	
	return {"Response": "Task successfully changed its status"}	
		
@app.put("/update_task/{id}", status_code=status.HTTP_201_CREATED) 
def update_task(id: str, upd: schemas.TaskUPD, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_task.mechanicals=upd.mechanicals
	db_task.hour=upd.hour
	db_task.task_price=upd.task_price
	db_task.hour_men=(upd.hour * upd.mechanicals)
	db.commit()
	db.refresh(db_task)	
	return db_task	

@app.delete("/delete_task/{id}", status_code=status.HTTP_201_CREATED) 
def delete_task(id: str, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")	
	db.delete(db_task)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#########################
#------EQUIPMENT--------- 
#########################
@app.post("/create_equipment/", status_code=status.HTTP_201_CREATED) 
def create_equipment(equipment: schemas.Equipment, db: Session = Depends(get_db)):		
	try:	
		equipments_in_db = db.query(
							models.Equipment.id,
							models.Equipment.equipment_name,
							models.Labor.type,							
							(models.Labor.id).label('labor_parent')
							).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
						).filter_by(equipment_name = equipment.equipment_name
						).filter_by(labor_equipment_id = equipment.labor_equipment_id
						).all()	
		if 	len(equipments_in_db) == 0:		
			db_equipment = models.Equipment(
				equipment_name=equipment.equipment_name,	
				equipment_quantity=equipment.equipment_quantity,
				equipment_unit_price=equipment.equipment_unit_price,  
				equipment_amount=(equipment.equipment_unit_price * equipment.equipment_quantity), 
				labor_equipment_id=equipment.labor_equipment_id,
			)			
			db_parent_labor = db.query(models.Labor).filter(models.Labor.id == equipment.labor_equipment_id).first()
			db_parent_labor.equipments.append(db_equipment)	
			db.add(db_equipment)   	
			db.commit()
			db.refresh(db_equipment)			
			return db_equipment
		else:
			raise HTTPException(status_code=500, detail="Equipment already exists in selected Labor")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating equipment")		

@app.get("/read_equipments/", status_code=status.HTTP_201_CREATED)  
def read_equipments(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_equipments = db.query(
					models.Equipment.id,
					models.Equipment.equipment_name,
					models.Equipment.equipment_quantity,					
					models.Equipment.equipment_unit_price,
					models.Equipment.equipment_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_equipment'),
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).all()	
	
	return db_equipments
	
@app.get("/read_equipments_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
def read_equipments_by_labor_id(labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_equipments = db.query(
					models.Equipment.id,
					models.Equipment.equipment_name,
					models.Equipment.equipment_quantity,
					models.Equipment.equipment_unit_price,					
					models.Equipment.equipment_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_equipment'),
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).filter_by(labor_equipment_id = labor_id
				).all()	
	return db_equipments
	
@app.put("/update_equipment/{id}", status_code=status.HTTP_201_CREATED) 
def update_equipment(id: str, upd: schemas.EquipmentUPD, db: Session = Depends(get_db)):
	db_equipment = db.query(models.Equipment).filter(models.Equipment.id == id).first()
	if db_equipment is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_equipment.equipment_quantity=upd.equipment_quantity
	db_equipment.equipment_unit_price=upd.equipment_unit_price
	db_equipment.equipment_amount=(upd.equipment_quantity * upd.equipment_unit_price)
	db.commit()
	db.refresh(db_equipment)	
	return db_equipment	

@app.delete("/delete_equipment/{id}", status_code=status.HTTP_201_CREATED) 
def delete_equipment(id: str, db: Session = Depends(get_db)):
	db_equipment = db.query(models.Equipment).filter(models.Equipment.id == id).first()
	if db_equipment is None:
		raise HTTPException(status_code=404, detail="Task not found")	
	db.delete(db_equipment)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}
	
#########################
#-------MATERIAL---------
#########################	

@app.post("/create_material/", status_code=status.HTTP_201_CREATED) 
def create_material(material: schemas.Material, db: Session = Depends(get_db)):		
	try:	
		materials_in_db = db.query(
							models.Material.id,
							models.Material.material_name,
							models.Labor.type,							
							(models.Labor.id).label('labor_parent')
							).join(models.Material, models.Labor.id == models.Material.labor_material_id
						).filter_by(material_name = material.material_name
						).filter_by(labor_material_id = material.labor_material_id
						).all()	
		if 	len(materials_in_db) == 0:		
			db_material = models.Material(
				material_name=material.material_name,	
				material_type=material.material_type,
				material_quantity=material.material_quantity,
				material_price=material.material_price,  
				material_amount=(material.material_price * material.material_quantity), 
				labor_material_id=material.labor_material_id,
			)			
			db_parent_labor = db.query(models.Labor).filter(models.Labor.id == material.labor_material_id).first()
			db_parent_labor.materials.append(db_material)	
			db.add(db_material)   	
			db.commit()
			db.refresh(db_material)			
			return db_material
		else:
			raise HTTPException(status_code=500, detail="Material already exists in selected Labor")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating material")		

@app.get("/read_materials/", status_code=status.HTTP_201_CREATED)  
def read_materials(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_materials = db.query(
					models.Material.id,
					models.Material.material_name,
					models.Material.material_type,
					models.Material.material_quantity,					
					models.Material.material_price,
					models.Material.material_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_material'),
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).all()	
	
	return db_materials
	
@app.get("/read_materials_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
def read_materials_by_labor_id(labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_materials = db.query(
					models.Material.id,
					models.Material.material_name,
					models.Material.material_type,
					models.Material.material_quantity,		
					models.Material.material_price,							
					models.Material.material_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_material'),
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).filter_by(labor_material_id = labor_id
				).all()	
	return db_materials
	
@app.put("/update_material/{id}", status_code=status.HTTP_201_CREATED) 
def update_material(id: str, upd: schemas.MaterialUPD, db: Session = Depends(get_db)):
	db_material = db.query(models.Material).filter(models.Material.id == id).first()
	if db_material is None:
		raise HTTPException(status_code=404, detail="Material not found")
	db_material.material_quantity=upd.material_quantity
	db_material.material_price=upd.material_price
	db_material.material_amount=(upd.material_quantity * upd.material_price)
	db.commit()
	db.refresh(db_material)	
	return db_material

@app.delete("/delete_material/{id}", status_code=status.HTTP_201_CREATED) 
def delete_material(id: str, db: Session = Depends(get_db)):
	db_material = db.query(models.Material).filter(models.Material.id == id).first()
	if db_material is None:
		raise HTTPException(status_code=404, detail="Material not found")	
	db.delete(db_material)	
	db.commit()
	return {"Response": "Delete Successfuly"}
	
##################################
###  STATISTICS FOR LABORS ID  ####
##################################

#------------Example queries TASK here----------

@app.get("/summary_amount_tasks_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
def summary_amount_tasks_by_labor_id(labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_project_summary = db.query(
					models.Labor.type,
					func.sum(models.Task.hour_men).label('hour_men'),
					func.sum(models.Task.task_price).label('task_price'),
					func.count(models.Task.id).label('task_number'),
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				#).filter(models.Labor.is_active == True, #models.Task.is_active == True
				).filter_by(labor_task_id = labor_id
				).all()	
	return db_project_summary

@app.get("/summary_tasks_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
def summary_tasks_by_project_id(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_amount'),
	).select_from(
		models.Task
	#).filter(
	#	models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_amount).label('task_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Labor.id		
	).all()
	
	return query

@app.get("/summary_all_tasks_by_projects/", status_code=status.HTTP_201_CREATED)  
def summary_all_tasks_by_projects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_amount'),
	).select_from(
		models.Task
	#).filter(
	#	models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		#models.Labor.type,
		#models.Labor.id.label('labor_id'),
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_amount).label('task_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).group_by(
		models.Project.id, models.Labor.id		
	).all()
	
	return query
	
@app.get("/summary_all_tasks/", status_code=status.HTTP_201_CREATED)  
def summary_all_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_price).label('task_price'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).all()
	
	return query
	
#------------Example queries EQUIPMENT here----------

@app.get("/summary_amount_equipments_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
def summary_amount_equipments_by_labor_id(labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_project_summary = db.query(
					models.Labor.type,
					func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
					func.count(models.Equipment.id).label('equipment_number'),
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				#).filter(models.Labor.is_active == True
				).filter_by(labor_equipment_id = labor_id
				).all()	
	return db_project_summary

@app.get("/summary_equipments_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
def summary_equipments_by_project_id(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Labor.id		
	).all()
	
	return query

@app.get("/summary_all_equipments_by_projects/", status_code=status.HTTP_201_CREATED)  
def summary_all_equipments_by_projects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		#models.Labor.type,
		#models.Labor.id.label('labor_id'),
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).group_by(
		models.Project.id, models.Labor.id		
	).all()
	
	return query
	
@app.get("/summary_all_equipments/", status_code=status.HTTP_201_CREATED)  
def summary_all_equipments(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).all()
	
	return query
	
#------------Example queries MATERIAL here----------

@app.get("/summary_amount_materials_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
def summary_amount_materials_by_labor_id(labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_project_summary = db.query(
					models.Labor.type,
					models.Material.material_type,
					func.sum(models.Material.material_amount).label('material_amount'),
					func.count(models.Material.id).label('material_number'),
					func.count(models.Material.material_type).label('material_number'),
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).filter_by(labor_material_id = labor_id
				).group_by(models.Material.material_type				
				).all()	
	return db_project_summary

@app.get("/summary_materials_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
def summary_materials_by_project_id(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	query = db.query(
		models.Labor.id,
		models.Labor.type,
		sub_query.c.material_type.label('material_type'),
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Labor.id, sub_query.c.material_type.label('material_type')
	).all()
	
	return query

@app.get("/summary_all_materials_by_projects/", status_code=status.HTTP_201_CREATED)  
def summary_all_materials_by_projects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		#models.Labor.type,
		#models.Labor.id.label('labor_id'),
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	#).filter(
	#	models.Labor.is_active == True 	
	).group_by(
		models.Project.id, models.Labor.id	
	).all()
	
	return query
	
@app.get("/summary_all_materials/", status_code=status.HTTP_201_CREATED)  
def summary_all_materials(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).all()
	
	return query
	
#--------------------ACTIVE TASK- BY PROJECTS--------------

@app.get("/summary_task_active_status_by_project/", status_code=status.HTTP_201_CREATED)  
def summary_task_active_status_by_project(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query_active = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('number_active'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_query_total = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('total_number'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		models.Labor.type,
		models.Labor.id.label('labor_id'),
		sub_query_total.c.total_number.label('total_number'),
		sub_query_active.c.number_active.label('number_active'),
		(sub_query_total.c.total_number - sub_query_active.c.number_active).label('diff_active'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query_active, sub_query_active.c.labor_id == models.Labor.id
	).join(
		sub_query_total, sub_query_total.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id, models.Labor.id	
	).all()
	
	return query
	
@app.get("/summary_task_active_status_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
def summary_task_active_status_by_project_id(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query_active = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('number_active'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_query_total = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('total_number'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		models.Labor.type,
		models.Labor.id.label('labor_id'),
		sub_query_total.c.total_number.label('total_number'),
		sub_query_active.c.number_active.label('number_active'),
		(sub_query_total.c.total_number - sub_query_active.c.number_active).label('diff_active'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query_active, sub_query_active.c.labor_id == models.Labor.id
	).join(
		sub_query_total, sub_query_total.c.labor_id == models.Labor.id
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Project.id, models.Labor.id	
	).all()
	
	return query

#--------------TOP PROJECTS------------	

@app.get("/project_materials_top/", status_code=status.HTTP_201_CREATED)  
def project_materials_top(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id	
	).order_by(
		sub_query.c.material_amount.desc()
	).first()	
	
	return query
	
@app.get("/project_tasks_top/", status_code=status.HTTP_201_CREATED)  
def project_tasks_top(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_material_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.task_price).label('task_amount'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.task_amount).label('task_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id	
	).order_by(
		sub_query.c.task_amount.desc()
	).first()	
	
	return query
	
@app.get("/project_equipments_top/", status_code=status.HTTP_201_CREATED)  
def project_equipments_top(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id	
	).order_by(
		sub_query.c.equipment_amount.desc()
	).first()	
	
	return query
