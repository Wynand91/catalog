# PROJECT: Item Catalog

The application provides a list of items (if there are any) within a variety of categories. User authentication is handled by OAuth. 
Authenticated users can add new items as well as edit/delete their own items.  

##### Please note! Edit and Delete buttons are not visible for items belonging to another user, or for users that are not authenticated.

## Dependencies:

    Python 3.5+
    
## Installation of Virtual Machine(VM):

Using vagrant/virtualbox (Recommended):

   1. Download vagrant [here](https://www.vagrantup.com/downloads.html)
   2. Download VirtualBox [here](https://www.virtualbox.org/)
   3. Download VM configurations zip file(FSND-Virtual-Machine) and unzip [here](https://s3.amazonaws.com/video.udacity-data.com/topher/2018/April/5acfbfa3_fsnd-virtual-machine/fsnd-virtual-machine.zip)
   4. From your terminal, inside FSND-Virtual-Machine/vagrant run: `vagrant up`
   5. After step 4 is finished run: `vagrant ssh`
   6. Your terminal is now logged into your virtual machine!
   
   Move the 'catalog' project folder into FSND-Virtual-Machine/vagrant. Install all requirements and run 'application.py' from here. Visit
   http://localhost:8000 locally to view app.
    
## Requirements:

   1. cd to project folder. 
   2. Activate virtual environment if necessary.
   3. Run `pip install -r requirements.txt`    

## How to run:

   1. Install necessary requirements/dependencies (preferably in a virtual environment)
   2. In terminal, cd to directory containing the `application.py` script
   3. With VM running - run `python application.py`
   4. Visit http://localhost:8000 locally to view app.
   
## JSON API

   If user is authenticated, the following JSON endpoints can be accessed:
   
     - JSON data of all items: http://localhost:8000/catalog/items/JSON
     - JSON data of a specific item (where <item_id> is the id of requested item): http://localhost:8000/catalog/item/<item_id>/JSON
## Author

 - Wynand theron
 
 
### Sources

FSND-Virtual-Machine configurations supplied by: [Udacity](https://www.udacity.com/)


## License

MIT License

Copyright (c) 2019 Wynand Theron

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.