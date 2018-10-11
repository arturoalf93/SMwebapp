from models import rfielements_providers, rfielements_analysts
from sqlalchemy import desc, func, and_, or_

def date_format(value):
	months = ("Enero","Febrero","Marzo","Abril","Mayo","Junio","Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre")
	month = months[value.month - 1]
	return "{} de {} del {}".format(value.day, month, value.year)

def previous_quarter_year(my_quarter, my_year):
	if my_quarter == 1:
		return_quarter = 4
		return_year = my_year - 1
	elif my_quarter in [2, 3, 4]:
		return_quarter = my_quarter - 1
		return_year = my_year
	else:
		sys.exit("Error when calling the function previous_quarter_year. Quarter is not either 1, 2, 3 or 4).")
	return [return_quarter, return_year]

def next_quarter_year(my_quarter, my_year):
	if my_quarter == 4:
		return_quarter = 1
		return_year = my_year + 1
	elif my_quarter in [1, 2, 3]:
		return_quarter = my_quarter + 1
		return_year = my_year
	else:
		sys.exit("Error when calling the function next_quarter_year. Quarter is not either 1, 2, 3 or 4).")
	return [return_quarter, return_year]

def last_self_score(my_vendor_id, my_smce_id, my_quarter, my_year):
	row_number_column = func.row_number().over(partition_by=(rfielements_providers.vendor_id, rfielements_providers.smce_id), order_by=(desc(rfielements_providers.year), desc(rfielements_providers.quarter), desc(rfielements_providers.round), desc(rfielements_providers.update_date))).label('row_order')
	return rfielements_providers.query.with_entities(rfielements_providers.self_score, row_number_column).filter_by(vendor_id = my_vendor_id, smce_id = my_smce_id).filter(or_(rfielements_providers.year < my_year, and_(rfielements_providers.year == my_year, rfielements_providers.quarter <= my_quarter))).from_self().filter(row_number_column == 1).first()[0]
		
def last_sm_score(my_vendor_id, my_smce_id, my_quarter, my_year):
	row_number_column = func.row_number().over(partition_by=(rfielements_analysts.vendor_id, rfielements_analysts.smce_id), order_by=(desc(rfielements_analysts.year), desc(rfielements_analysts.quarter), desc(rfielements_analysts.round), desc(rfielements_analysts.update_date))).label('row_order')
	return rfielements_analysts.query.with_entities(rfielements_analysts.sm_score, row_number_column).filter_by(vendor_id = my_vendor_id, smce_id = my_smce_id).filter(or_(rfielements_analysts.year < my_year, and_(rfielements_analysts.year == my_year, rfielements_analysts.quarter <= my_quarter))).from_self().filter(row_number_column == 1).first()[0]
		