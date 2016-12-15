struct Node *getNode(u_int16_t id, u_int16_t seq);
void addNode(char *newIp, u_int16_t id, u_int16_t seq);
bool removeNode(u_int16_t id, u_int16_t seq);
int getSize();

struct Node{
	struct Node *next;
	char *ip;
	u_int16_t id;
	u_int16_t seq;
};
int listSize = 0;
struct Node *first;
struct Node *last;

/* returns the number of nodes in the list */
int getSize(){
	return listSize;
}

/* returns the first node in the list */
struct Node *getNode(u_int16_t id, u_int16_t seq){
	if(listSize == 0){
		return (struct Node*)-1;
	}
	else{
		struct Node *curr = first;
		
		while(true){
			if(curr->id == id && curr->seq == seq){
				return curr;
			}
			if(curr->next == 0){
				break;
			}
			curr = curr->next;
		}
	}
	
	printf("getnode10\n");
	return (struct Node*)-1;
}

/* allocate and add a new node, move the last-pointer if listSize>0 */
void addNode(char *newIp, u_int16_t id, u_int16_t seq){
	if(listSize == 0){
		first = malloc(sizeof(struct Node));
		first->next = 0;
		first->ip = newIp;
		first->id = id;
		first->seq = seq;
		last = first;
	}
	else{
		struct Node *newNode;
		newNode = malloc(sizeof(struct Node));
		newNode->next = 0;
		newNode->ip = newIp;
		newNode->id = id;
		newNode->seq = seq;
		last->next = newNode;
		last = newNode;
	}

	listSize++;
}

/* remove and free the first node, move the first-pointer if listSize>1 */
bool removeNode(u_int16_t id, u_int16_t seq){
	if(listSize == 0){
		return false;
	}
	else{
		struct Node *temp = getNode(id, seq);
		
		if(temp == (struct Node*)-1){
			return false;
		}
		else{
			if(temp == first){
				if(listSize == 1){
					free(temp);
				}
				else{
					first = first->next;
					free(temp);
				}
			}
			else if(temp == last){
				struct Node *prev = first;
				while(true){
					if(prev->next == last){
						break;
					}
					prev = prev->next;
				}
				prev->next = 0;
				free(temp);
			}
			else{
				struct Node *prev = first;
				while(true){
					if(prev->next == temp){
						break;
					}
					prev = prev->next;
				}
				prev->next = temp->next;
				free(temp);
			}

			listSize--;
			return true;
		}
	}
}
