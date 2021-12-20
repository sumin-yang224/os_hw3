//
// Virual Memory Simulator Homework
// One-level page table system with FIFO and LRU
// Two-level page table system with LRU
// Inverted page table with a hashing system 
// Submission Year: 2021-11-20
// Student Name: Yang Su Min
// Student Number: B711107
//
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define PAGESIZEBITS 12			// page size = 4Kbytes
#define VIRTUALADDRBITS 32		// virtual address space size = 4Gbytes
#define TRUE 1
#define FALSE 0
#define MASK 0x00000fff
#define DEFAULT -1

struct procEntry {
	char *traceName;			// the memory trace name
	int pid;					// process (trace) id
	int ntraces;				// the number of memory traces
	int num2ndLevelPageTable;	// The 2nd level page created(allocated);
	int numIHTConflictAccess; 	// The number of Inverted Hash Table Conflict Accesses
	int numIHTNULLAccess;		// The number of Empty Inverted Hash Table Accesses
	int numIHTNonNULLAccess;		// The number of Non Empty Inverted Hash Table Accesses
	int numPageFault;			// The number of page faults
	int numPageHit;				// The number of page hits
	struct pageTableEntry *firstLevelPageTable;
	FILE *tracefp;
};

struct pageTableEntry{
	int valid;
	int frameNum;
	struct pageTableEntry* secondLevelPageTable;
};

struct invertedHashTableEntry{
	int pid;
	int pageNum;
	int frameNum;
	struct invertedHashTableEntry* prev;
	struct invertedHashTableEntry* next;
};

struct framePage{
	int pid;
	int frameNum;
	int firstpageNum;
	int secondpageNum;
	struct framePage* prev;
	struct framePage* next;
};

int numProcess, nFrame, firstlevelbits, secondlevelbits, phyMemSizeBits;
int optind;
struct framePage* oldestframe;

void initHashTable(struct invertedHashTableEntry* hashTable){
	int i;
	for(i=0;i<nFrame;i++){
		hashTable[i].pid = DEFAULT;
		hashTable[i].pageNum = DEFAULT;
		hashTable[i].frameNum = DEFAULT;
		hashTable[i].prev = NULL;
		hashTable[i].next = NULL;
	}
}
void initPhyMem(struct framePage* phyMem){
	int i;
	for(i=0; i < nFrame; i++){
		phyMem[i].frameNum = i;
		phyMem[i].pid = DEFAULT;
		phyMem[i].firstpageNum = DEFAULT;
		phyMem[i].secondpageNum = DEFAULT;
		phyMem[i].prev = &phyMem[(i-1+nFrame)%nFrame];
		phyMem[i].next = &phyMem[(i+1+nFrame)%nFrame];
	}
}

void initPageTable(struct pageTableEntry* pageTable, int pageEntryNum){
	int i;
	for(i=0; i< pageEntryNum; i++){
		pageTable[i].frameNum=DEFAULT;
		pageTable[i].valid=0;
		pageTable[i].secondLevelPageTable=NULL;
	}
}

int hash(int pageNum, int pid){
	return (pageNum+pid)%nFrame;
}

struct framePage* replacement(struct framePage* phyMem){
	struct framePage* ret = oldestframe;
	oldestframe = oldestframe->next;
	return ret;
}

void LRU_update(struct framePage* phyMem, int PFN){
	if(phyMem[PFN].frameNum == oldestframe->frameNum){
		oldestframe = oldestframe->next;
	}
	else{
		phyMem[PFN].prev->next = phyMem[PFN].next;
		phyMem[PFN].next->prev = phyMem[PFN].prev;

		phyMem[PFN].prev = oldestframe->prev;
		phyMem[PFN].next = oldestframe;
	
		oldestframe->prev->next = &phyMem[PFN];
		oldestframe->prev = &phyMem[PFN];
	}
}

void oneLevelVMSim(struct procEntry* procTable, struct framePage* phyMem, int simType) {
	int i, count=0;
	unsigned int Vaddr, Paddr, VPN, PFN, offset;
	char rw;
	struct framePage* ret;

	oldestframe = phyMem;

	for (i=0;i<numProcess;i++){
		procTable[i].firstLevelPageTable= (struct pageTableEntry*)malloc(sizeof(struct pageTableEntry) * (1<<firstlevelbits));
		initPageTable(procTable[i].firstLevelPageTable, (1<<firstlevelbits));
	}

	while(count<numProcess){
		for(i=0; i < numProcess; i++){	
			if(procTable[i].tracefp==NULL) continue;
			if(fscanf(procTable[i].tracefp, "%x %c", &Vaddr, &rw)==EOF) {
				count++;
				if(fclose(procTable[i].tracefp)){
					printf("fclose error : process %d\n", i);
					exit(1);
				};
				continue;
			}
			
			VPN = Vaddr >> PAGESIZEBITS;
			offset = Vaddr & MASK;

			//page hit
			if(procTable[i].firstLevelPageTable[VPN].valid==1){
				PFN = procTable[i].firstLevelPageTable[VPN].frameNum;
				if(simType==1) LRU_update(phyMem, PFN);
				procTable[i].numPageHit++;
			}
			else{	// page fault
				/* page replacement algorithm */
				ret = replacement(phyMem);
				
				// update PageTable & phyMem
				if(ret->pid !=-1) procTable[ret->pid].firstLevelPageTable[ret->firstpageNum].valid =0;
				ret->pid=i;
				ret->firstpageNum = VPN;
				procTable[i].firstLevelPageTable[VPN].frameNum = ret->frameNum;
				procTable[i].firstLevelPageTable[VPN].valid = 1;

				PFN = ret->frameNum;
				procTable[i].numPageFault++;
			}

			Paddr = PFN << PAGESIZEBITS;
			Paddr = Paddr | offset;
			procTable[i].ntraces++;
			if(optind == TRUE) 
				printf("One-Level procID %d traceNumber %d virtual addr %x physical addr %x\n", 
					i, procTable[i].ntraces, Vaddr, Paddr);
		}
	}
	for(i=0; i < numProcess; i++) {
		printf("**** %s *****\n",procTable[i].traceName);
		printf("Proc %d Num of traces %d\n",i,procTable[i].ntraces);
		printf("Proc %d Num of Page Faults %d\n",i,procTable[i].numPageFault);
		printf("Proc %d Num of Page Hit %d\n",i,procTable[i].numPageHit);
		assert(procTable[i].numPageHit + procTable[i].numPageFault == procTable[i].ntraces);
	}
	
	for(i=0; i< numProcess; i++)
		free(procTable[i].firstLevelPageTable);
}
void twoLevelVMSim(struct procEntry* procTable, struct framePage* phyMem) {
	int i,j,count=0;
	unsigned int Vaddr, Paddr, firstlevelVPN, secondlevelVPN, PFN, offset, temp;
	char rw;
	struct framePage* ret;

	oldestframe = phyMem;

	for(i=0; i < numProcess; i++){
		procTable[i].firstLevelPageTable= (struct pageTableEntry*)malloc(sizeof(struct pageTableEntry) * (1<<firstlevelbits));
		initPageTable(procTable[i].firstLevelPageTable, (1<<firstlevelbits));
	}

	while(count<numProcess){
		for(i=0; i < numProcess; i++){	
			if(procTable[i].tracefp==NULL) continue;
			if(fscanf(procTable[i].tracefp, "%x %c", &Vaddr, &rw)==EOF) {
				count++;
				if(fclose(procTable[i].tracefp)){
					printf("fclose error : process %d\n", i);
					exit(1);
				};
				continue;
			}
			
			firstlevelVPN = Vaddr >> secondlevelbits + PAGESIZEBITS;
			offset = Vaddr & MASK;

			temp = firstlevelVPN << secondlevelbits + PAGESIZEBITS;
			temp = Vaddr & ~temp;
			secondlevelVPN = temp >> PAGESIZEBITS;

			//firstlevelPageTable page hit
			if(procTable[i].firstLevelPageTable[firstlevelVPN].valid==1){
				
				//secondlevelPageTable page hit
				if(procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable[secondlevelVPN].valid==1){
					PFN = procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable[secondlevelVPN].frameNum;
					LRU_update(phyMem, PFN);
					procTable[i].numPageHit++;
				}
				//secondlevelPageTable page fault
				else{
					/* page replacement algorithm */
					ret = replacement(phyMem);

					// update PageTable & phyMem
					if(ret->pid !=-1) procTable[ret->pid].firstLevelPageTable[ret->firstpageNum].secondLevelPageTable[ret->secondpageNum].valid =0;
					ret->pid=i;
					ret->firstpageNum = firstlevelVPN;
					ret->secondpageNum = secondlevelVPN;
					procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable[secondlevelVPN].frameNum = ret->frameNum;
					procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable[secondlevelVPN].valid = 1;

					PFN = ret->frameNum;
					procTable[i].numPageFault++;
				}
				
			}
			else{	// firstlevelPageTable page fault
			
				// There's no secondlevelPageTable
				procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable = (struct pageTableEntry*)malloc(sizeof(struct pageTableEntry)*(1<<secondlevelbits));
				initPageTable(procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable, (1<<secondlevelbits));
				procTable[i].num2ndLevelPageTable++;
				
				/* page replacement algorithm */
				ret = replacement(phyMem);

				// update PageTable & phyMem
				if(ret->pid !=-1) procTable[ret->pid].firstLevelPageTable[ret->firstpageNum].secondLevelPageTable[ret->secondpageNum].valid =0;
				ret->pid=i;
				ret->firstpageNum = firstlevelVPN;
				ret->secondpageNum = secondlevelVPN;
				procTable[i].firstLevelPageTable[firstlevelVPN].valid =1;
				procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable[secondlevelVPN].frameNum = ret->frameNum;
				procTable[i].firstLevelPageTable[firstlevelVPN].secondLevelPageTable[secondlevelVPN].valid = 1;
				
				PFN = ret->frameNum;
				procTable[i].numPageFault++;
			}

			Paddr = PFN << PAGESIZEBITS;
			Paddr = Paddr | offset;
			procTable[i].ntraces++;
			if(optind == TRUE) 
				printf("Two-Level procID %d traceNumber %d virtual addr %x physical addr %x\n", 
					i, procTable[i].ntraces, Vaddr, Paddr);
		}
	}
	for(i=0; i < numProcess; i++) {
		printf("**** %s *****\n",procTable[i].traceName);
		printf("Proc %d Num of traces %d\n",i,procTable[i].ntraces);
		printf("Proc %d Num of second level page tables allocated %d\n",i,procTable[i].num2ndLevelPageTable);
		printf("Proc %d Num of Page Faults %d\n",i,procTable[i].numPageFault);
		printf("Proc %d Num of Page Hit %d\n",i,procTable[i].numPageHit);
		assert(procTable[i].numPageHit + procTable[i].numPageFault == procTable[i].ntraces);
	}

	for(i=0; i < numProcess; i++){
		for(j=0; j < (1<<firstlevelbits); j++){
			if(procTable[i].firstLevelPageTable[j].secondLevelPageTable !=NULL) 
				free(procTable[i].firstLevelPageTable[j].secondLevelPageTable);
		}
		free(procTable[i].firstLevelPageTable);
	}
}

void invertedPageVMSim(struct procEntry* procTable, struct framePage* phyMem) {
	int i, flag, count=0;
	unsigned int Vaddr, Paddr, VPN, PFN, offset, index;
	char rw;
	struct framePage* ret;
	struct invertedHashTableEntry* hashTable = (struct invertedHashTableEntry*)malloc(sizeof(struct invertedHashTableEntry) * nFrame);
	initHashTable(hashTable);

	oldestframe = phyMem;
	
	while(count<numProcess){
		for(i=0; i < numProcess; i++){	
			if(procTable[i].tracefp==NULL) continue;
			if(fscanf(procTable[i].tracefp, "%x %c", &Vaddr, &rw)==EOF) {
				count++;
				if(fclose(procTable[i].tracefp)){
					printf("fclose error : process %d\n", i);
					exit(1);
				};
				continue;
			}
			
			VPN = Vaddr >> PAGESIZEBITS;
			offset = Vaddr & MASK;
			index = hash(VPN, i);
			
			flag = FALSE;
			struct invertedHashTableEntry* iter = hashTable[index].next;

			/* need to modify*/
			if(iter==NULL) procTable[i].numIHTNULLAccess++;
			else procTable[i].numIHTNonNULLAccess++;	

			/* find Entry */
			while(iter!=NULL){
				procTable[i].numIHTConflictAccess++;
				if(iter->pid==i && iter->pageNum == VPN) {
					flag = TRUE; break;
				}
				iter = iter->next;
			}

			// There's a Entry
			if(flag){
				//page hit
				PFN = iter->frameNum;
				LRU_update(phyMem, PFN);
				procTable[i].numPageHit++;
			} 
			// There's no Entry
			else { 
				/* page replacement algorithm */
				ret = replacement(phyMem);

				// update phyMem
				if(ret->pid !=-1){
					struct invertedHashTableEntry* tmp = hashTable[hash(ret->firstpageNum,ret->pid)].next;
					while(tmp!=NULL){
						if(tmp->pageNum == ret->firstpageNum && tmp->pid == ret->pid) break;
						tmp = tmp->next;
					}
					// tmp modify
					tmp->prev->next = tmp->next;
					if(tmp->next != NULL) tmp->next->prev = tmp->prev;

					free(tmp);
				}
				ret->pid = i;
				ret->firstpageNum = VPN;

				/* make new Entry*/
				struct invertedHashTableEntry* hashNode = (struct invertedHashTableEntry*)malloc(sizeof(struct invertedHashTableEntry));
				hashNode->pid = i;
				hashNode->pageNum = VPN;
				hashNode->frameNum = ret->frameNum;
				hashNode->prev = &hashTable[index];
				hashNode->next = hashTable[index].next;

				/* update hash table */
				if(hashNode->next != NULL) hashNode->next->prev = hashNode;
				hashTable[index].next = hashNode;
				procTable[i].numPageFault++;
			}
			
			Paddr = PFN << PAGESIZEBITS;
			Paddr = Paddr | offset;
			procTable[i].ntraces++;
			if(optind == TRUE) 
				printf("ITH procID %d traceNumber %d virtual addr %x physical addr %x\n", 
					i, procTable[i].ntraces, Vaddr, Paddr);
		}
	}

	for(i=0; i < numProcess; i++) {
		printf("**** %s *****\n",procTable[i].traceName);
		printf("Proc %d Num of traces %d\n",i,procTable[i].ntraces);
		printf("Proc %d Num of Inverted Hash Table Access Conflicts %d\n",i,procTable[i].numIHTConflictAccess);
		printf("Proc %d Num of Empty Inverted Hash Table Access %d\n",i,procTable[i].numIHTNULLAccess);
		printf("Proc %d Num of Non-Empty Inverted Hash Table Access %d\n",i,procTable[i].numIHTNonNULLAccess);
		printf("Proc %d Num of Page Faults %d\n",i,procTable[i].numPageFault);
		printf("Proc %d Num of Page Hit %d\n",i,procTable[i].numPageHit);
		assert(procTable[i].numPageHit + procTable[i].numPageFault == procTable[i].ntraces);
		assert(procTable[i].numIHTNULLAccess + procTable[i].numIHTNonNULLAccess == procTable[i].ntraces);
	}

	for(i=0;i<nFrame;i++){
		struct invertedHashTableEntry* iter = hashTable[i].next;
		while(iter!=NULL){
			struct invertedHashTableEntry* tmp = iter;
			iter = iter->next;
			free(tmp);
		}
	}
	free(hashTable);
}

int main(int argc, char *argv[]) 
{
	int i,c, simType;

	if(strcmp(argv[1], "-s")==0) optind =TRUE;
	else optind = FALSE;

	simType = atoi(argv[1+optind]);
	firstlevelbits = atoi(argv[2+optind]);
	phyMemSizeBits = atoi(argv[3+optind]);
	
	if(simType == 0 || simType == 1 ) {
		firstlevelbits = VIRTUALADDRBITS-PAGESIZEBITS;
		secondlevelbits = DEFAULT;
	}
	else {
		secondlevelbits = VIRTUALADDRBITS-PAGESIZEBITS - firstlevelbits;	
		assert(secondlevelbits>0);
	}
	
	numProcess = argc - 4 - optind;
	nFrame = 1<<(phyMemSizeBits-PAGESIZEBITS);
	assert(nFrame>0);

	struct procEntry* procTable = (struct procEntry*)malloc(sizeof(struct procEntry) * numProcess);
	struct framePage* phyMem = (struct framePage*)malloc(sizeof(struct framePage) * nFrame);

	initPhyMem(phyMem);
	
	// initialize procTable for Memory Simulations
	for(i = 0; i < numProcess; i++) {
		procTable[i].pid=i;	
		procTable[i].ntraces=0;
		procTable[i].numPageHit=0;
		procTable[i].numPageFault=0;
		procTable[i].numIHTNULLAccess=0;
		procTable[i].numIHTNonNULLAccess=0;
		procTable[i].numIHTConflictAccess=0;
		procTable[i].num2ndLevelPageTable=0;
		procTable[i].traceName= argv[i+optind+4];
		procTable[i].firstLevelPageTable = NULL;
		

		// opening a tracefile for the process
		printf("process %d opening %s\n",i,argv[i + optind + 4]);
		procTable[i].tracefp = fopen(argv[i + optind + 4],"r");
		if (procTable[i].tracefp == NULL) {
			printf("ERROR: can't open %s file; exiting...",argv[i+optind+4]);
			exit(1);
		}
	}

	printf("Num of Frames %d Physical Memory Size %ld bytes\n",nFrame, (1L<<phyMemSizeBits));
	
	if (simType == 0) {
		printf("=============================================================\n");
		printf("The One-Level Page Table with FIFO Memory Simulation Starts .....\n");
		printf("=============================================================\n");
		oneLevelVMSim(procTable, phyMem, simType);
	}
	
	if (simType == 1) {
		printf("=============================================================\n");
		printf("The One-Level Page Table with LRU Memory Simulation Starts .....\n");
		printf("=============================================================\n");
		oneLevelVMSim(procTable, phyMem, simType);
	}
	
	if (simType == 2) {
		printf("=============================================================\n");
		printf("The Two-Level Page Table Memory Simulation Starts .....\n");
		printf("=============================================================\n");
		twoLevelVMSim(procTable, phyMem);
	}
	
	if (simType == 3) {
		printf("=============================================================\n");
		printf("The Inverted Page Table Memory Simulation Starts .....\n");
		printf("=============================================================\n");
		invertedPageVMSim(procTable, phyMem);
	}
	free(procTable);
	free(phyMem);
	return(0);
}
