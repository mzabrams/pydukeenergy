# pydukeenergy
Python3 interface to the unofficial Duke Energy API.

**NOTE** This isn't using an official API therefore this library could stop working at any time, without warning.

```python
from pydukeenergy.api import DukeEnergy

def main():
	# update_interval is optional default is 60 minutes
    duke = DukeEnergy(
        email = "your_user_name", 
        password = "your_password", 
        electric_meters=[12341234,56785678], 
        gas_meters = [11223344,55667788],
        update_interval=60,
        verify = True
    )
    meters = duke.get_meters()
    for meter in meters:
    	print(meter.get_usage())
```