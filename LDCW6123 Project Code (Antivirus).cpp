#include <iostream> 
#include <string>
#include <cstdlib>

//pulls all standard components into global scope allows omission of std:: prefix in front of components of the std container
using namespace std;

//setting constants to ease debugging
const int PROGRAM_COUNT = 12;
const int SIGNATURE_COUNT = 6;
const int HISTORY_SIZE = 60;

//record for programs to store program details required
struct Programs{
	string name;
	string data;
	int originalChecksum;
	int currentChecksum;
	int heuristicScore;
	string Status;
};

//record to store history of actions performed using the antivirus
struct HistoryRecord{
	string scanType;
	string programName;
	string result;
};

//an array to store names of viruses for virus database
string virusNames[SIGNATURE_COUNT] = {
	"Brain", "Stoned", "Jerusalem", "Michelangelo", "Melissa", "ILOVEYOU"
};

//an array to store signatures of viruses for virus database
string virusSignatures[SIGNATURE_COUNT] = {
	"BRAIN", "STONED", "JERU", "MICHEL", "MELISSA", "LOVE-LETTER"
};

//2D record of programs that are simulated within this program
Programs SimulatedPrograms[PROGRAM_COUNT] = {
	{"SYSTEM Utility", "BOOT SYSTEM CLEAN", 1260, 1260, 35, "ACTIVE"},
	{"GAME Program", "PLAYER LEVEL SCORE", 1420, 1420, 10, "ACTIVE"},
	{"DOWNLOAD Setup", "INSTALL BRAIN PAYLOAD", 1880, 1880, 80, "ACTIVE"},
	{"EMAIL Attachment", "DOCUMENT JERU MACRO", 1730, 1730, 70, "ACTIVE"},
	{"PHOTO Editor", "IMAGE FILTER COLOUR", 1510, 1510, 15, "ACTIVE"},
	{"UPDATED Tool", "SYSTEM TOOL NEW VERSION", 1200, 1450, 55, "ACTIVE"},
	{"USB Boot Tool", "BOOT STONED SECTOR", 1650, 1650, 75, "ACTIVE"},
	{"OFFICE Document", "REPORT MELISSA MACRO", 1340, 1340, 65, "ACTIVE"},
	{"LOVE Letter", "LOVE-LETTER EMAIL SCRIPT", 1490, 1490, 90, "ACTIVE"},
	{"ART Program", "DRAW PAINT CANVAS", 1380, 1380, 5, "ACTIVE"},
	{"BACKUP Utility", "COPY ARCHIVE STORAGE", 1550, 1550, 30, "ACTIVE"},
	{"OLD Boot Disk", "MICHEL BOOT SAMPLE", 1600, 1600, 85, "ACTIVE"}
};

//initializing the history record allowing it to store application history
HistoryRecord historyList[HISTORY_SIZE];
int historyCount = 0;

//function prototypes for helper functions
string getRiskLevel(int score);
void addHistory(string scanType, string programName, string result);
int findSignature(string programData);
void scanOneProgram(int programIndex, string scanType);

//function prototypes for main functions
void mainMenu();
void quickScan();
void fullScan();
void customThreatAnalysis();
void virusDatabase();
void Quarantine();
void integrityCheck();
void history();

//main fucntion
int main() {
	int choice = 0; //initializing choice
	
	//a while loop which runs the program continuously until the user terminates it
	while (choice != 8) {
		system("cls"); //ensures the concole is cleared
		mainMenu();
		
		cout << "Enter Choice <1-8>: \n";
		cin >> choice;
		
		//loop to catch user input errors
		while (choice < 1 || choice > 8){
			cout << "Invalid Choice! Please Enter a number between 1-8."; 
			cin >> choice;
		}
		
		//switch case which allows user to select which case to perform
		switch (choice){
			case 1:
				quickScan();
				break;
				
			case 2:
				fullScan();
				break;
				
			case 3:
				customThreatAnalysis();
				break;
				
			case 4:
				virusDatabase();
				break;
				
			case 5:
				Quarantine();
				break;
				
			case 6:
				integrityCheck();
				break;
				
			case 7:
				history();
				break;
				
			case 8:
				system("cls");
				cout << "Program Terminated\n";
				break;
		}
	}
	return 0;
}

//displays main menu
void mainMenu(){
	cout << "\n================== Simulated Antivirus ===================\n";
	cout << "1. Quick Scan\n";
	cout << "2. Full Scan\n";
	cout << "3. Custom Threat Analysis\n";
	cout << "4. Virus Database\n";
	cout << "5. Quarantine\n";
	cout << "6. Integrity Check\n";
	cout << "7. Scan History\n";
	cout << "8. End Program\n";
	cout << "============================================================\n";
}

//helper function to search for matches with the virus database
int findSignature(string programData) {
	for (int i = 0; i < SIGNATURE_COUNT; i++) { //for loop to progress through each item in the virus signature array
		if (programData.find(virusSignatures[i]) != string::npos) { //searches programData array for strings matching items in the virusSignatures array returning the index number within the array
			return i;
		}
	}
	return -1;
}

//obtains risk level through condition testing
string getRiskLevel(int score){
	if(score <= 24){
		return "SAFE";
	} else if (score <=49) {
		return "LOW RISK";
	} else if (score <= 74) {
		return "SUSPICIOUS";
	} else {
		return "HIGH RISK";
	}
}

//helper function to add logs into the history array that was initialized
void addHistory(string scanType, string programName, string result){
	if(historyCount < HISTORY_SIZE){
		historyList[historyCount].scanType = scanType;
		historyList[historyCount].programName = programName;
		historyList[historyCount].result = result;
		historyCount++;
	}
}

//helper function to go through each program to find signatures matching the virus database
void scanOneProgram(int programIndex, string scanType){
	int signatureIndex = findSignature(SimulatedPrograms[programIndex].data); //utilizes findSignature helper function to find matches
	string result;
	
	cout << "\nScanning: " << SimulatedPrograms[programIndex].name << "\n";
	
	if(signatureIndex != -1){
		result = "KNOWN THREAT: " + virusNames[signatureIndex]; //returns the name of the virus
		cout << "Signature result : " << result << "\n"; //returns which program is affected
	} else {
		cout << "Signature result : NO MATCH\n"; //signatureIndex = -1 when no virus is found
		result = getRiskLevel(SimulatedPrograms[programIndex].heuristicScore); //sets result to the risk level of the program based on its heuristik score
	}
	
	cout << "Threat score: " << SimulatedPrograms[programIndex].heuristicScore << " / 100\n"; //returns the heuristic score
	cout << "Heuristic result: " << getRiskLevel(SimulatedPrograms[programIndex].heuristicScore) << "\n"; //returns the risk level based on the heuristic score
	cout << "Status: " << SimulatedPrograms[programIndex].Status << "\n";//returns status (active/quarantined)
	
	addHistory(scanType, SimulatedPrograms[programIndex].name, result);//adds this action into the history log
}

//performs "quick scan", skipping over some programs for a simulated quick scan by integrating the scanOneProgram helper function and giving it the index to "scan"
void quickScan() {
	system("cls");
	cout << "--- QUICK SCAN ---\n";
	scanOneProgram(0, "Quick");
	scanOneProgram(2, "Quick");
	scanOneProgram(3, "Quick");
	scanOneProgram(8, "Quick");
	cout << "\nQuick scan complete. \n";
	system("pause");
}

//runs scanOneProgram through each attribute within the SimulatedPrograms structure by utilizing a for loop
void fullScan(){
	system("cls");
	cout << "--- FULL SCAN ---\n";
	for(int i = 0; i < PROGRAM_COUNT; i++){
		scanOneProgram(i, "Full");
	}
	cout << "\nFull scan completed.\n";
	system("pause");
}

//obtains user input to carry out a "custom threat analysis" and gives it a score as well as a recommended action
void customThreatAnalysis() {
	int score = 0;
	int choice = 0;
	
	system("cls");
	cout << "--- CUSTOM HEURISTIC THREAT ANALYSIS ---\n";
	
	cout << "\nProgram type:\n";
	cout << "1. Official store (+0)\n";
	cout << "2. Script (+10)\n";
	cout << "3. Executable (+20)\n";
	cout << "0. Cancel Analysis\n";
	cout << "Choice: ";
	cin >> choice;
	if(choice == 0){
		system("cls");
		cout << "Analysis Cancelled.\n";
		system("pause");
		return;
	}
	if(choice == 2) score += 10;
	else if(choice == 3) score +=20;
	
	cout << "\nDownload score: \n";
	cout << "1. Official store (+0)\n";
	cout << "2. Unknown website (+15)\n";
	cout << "3. Untrusted scource (+25)\n";
	cout << "0. Cancel Analysis\n";
	cout << "Choice: ";
	cin >> choice;
	if(choice == 0){
		system("cls");
		cout << "Analysis Cancelled.\n";
		system("pause");
		return;
	}
	if (choice == 2) score += 15;
	else if (choice == 3) score += 25;
	
	cout << "\nObserved behaviour:\n";
	cout << "1. Normal behaviour (+0)\n";
	cout << "2. Changes system settings (+15)\n";
	cout << "3. Unknown network access (+25)\n";
	cout << "4. Disables security (+40)\n";
	cout << "5. Encypts many documents (+45)\n";
	cout << "0. Cancel Analysis\n";
	cout << "Choice: ";
	cin >> choice;
	if(choice == 0){
		system("cls");
		cout << "Analysis Cancelled\n";
		system("pause");
		return;
	}
	if (choice == 2) score += 15;
	else if (choice == 3) score += 25;
	else if (choice == 4) score += 40;
	else if (choice == 5) score += 45;
	
	cout << "\nIs the program packed or obufscated?\n";
	cout << "1. Yes (+15)\n";
	cout << "2. No (+0)\n";
	cout << "0. Cancel Analysis\n";
	cout << "Choice: ";
	cin >> choice;
	if(choice == 0){
		system("cls");
		cout << "Analysis Cancelled\n";
		system("pause");
		return;
	}
	if(choice == 1) score += 15;
	
	if (score > 100) {
		score = 100;
	}
	
	//if condition testing to ouput a recommended action at the end of the analysis
	cout << "\nThreat score : " << score << " / 100\n";
	cout << "Risk Level : " << getRiskLevel(score) << "\n";
	if(score <= 24) cout << "Recommended Action: Allow and monitor\n";
	else if (score <=49) cout << "Recommended Action: Check the source \n";
	else if (score <= 74) cout << "Recommended Action: Investigate carefully\n";
	else cout << "Recommended Action: Quarantine for investigation\n";
	
	addHistory("Custom", "User answer", getRiskLevel(score)); //adds the custom analysis into the history
	system("pause");
}

//a function to display all known viruses within this simulated antivirus
void virusDatabase() {
	system("cls");
	cout << "--- Virus Database ---\n";
	cout << "Database Version: 1.0\n";
	cout << "Known Threats : " << SIGNATURE_COUNT << "\n\n";
	cout << "Name\t\tSignature\n";
	for (int i = 0; i < SIGNATURE_COUNT; i++) {
		cout << virusNames[i] << "\t\t" << virusSignatures[i] << "\n";
	}
	system("pause");
}

//a function to allow users to select which programs to quarantine and return to main menu
void Quarantine() {
	int choice = 0;
	
	while (choice != PROGRAM_COUNT + 1) {
		system("cls");
		cout << "--- QUARANTINE ---\n";
		for (int i = 0; i < PROGRAM_COUNT; i++) {
			cout << i + 1 << ". " << SimulatedPrograms[i].name << " [" << SimulatedPrograms[i].Status << "]\n";	
		}
		cout << PROGRAM_COUNT + 1 << ". Return to main menu\n";
		
		cout << "Enter choice: ";
		cin >> choice;
		
		if (choice >= 1 && choice <= PROGRAM_COUNT) {
			int index = choice - 1;
			if (SimulatedPrograms[index].Status == "QUARANTINED"){
				system("cls");
				cout << "\n" << SimulatedPrograms[index].name << " is already QUARANTINED.\n";
			} else {
				system("cls");
				SimulatedPrograms[index].Status = "QUARANTINED";
				cout << "\n" << SimulatedPrograms[index].name << " is now QUARANTINED (simulation). \n";
				addHistory("Action", SimulatedPrograms[index].name, "QUARANTINED");
			}
			cout << "\n";
			system("pause");
		}
	}
}

void integrityCheck() {
	int choice = 0;
	
	while(choice != PROGRAM_COUNT + 1) {
		system("cls");
		cout << "--- INTEGRITY CHECK ---\n";
		for (int i = 0; i < PROGRAM_COUNT; i++) {
			cout << i + 1 << ". " << SimulatedPrograms[i].name << "\n";
		}
		cout << PROGRAM_COUNT + 1 << ". Return to main menu\n";
		
		cout << "Enter choice: ";
		cin >> choice;
		
		system("cls");
		if (choice >= 1 && choice <= PROGRAM_COUNT) {
			int index = choice - 1;
			cout << "Program: " << SimulatedPrograms[index].name;
			cout << "\nOriginal checksum: " << SimulatedPrograms[index].originalChecksum << "\n";
			cout << "Current checksum: " << SimulatedPrograms[index].currentChecksum << "\n";
			
			if (SimulatedPrograms[index].originalChecksum == SimulatedPrograms[index].currentChecksum) {
				cout << "Result: No change detected.\n";
				addHistory("Integrity", SimulatedPrograms[index].name, "UNCHANGED");
			}else {
				cout << "Result: WARNING! Program has been modified.\n";
				addHistory("Integrity", SimulatedPrograms[index].name, "MODIFIED");
			}
			cout << "\n";
			system("pause");
		}
	}
}

void history() {
	cout << "--- Current Session History ---\n";
	if(historyCount == 0) {
		cout << "No scans or actions recorded yet.\n";
		return;
	}
	
	for (int i = 0; i< historyCount; i++) {
		cout << i + 1 << ". [" << historyList[i].scanType << "] "
			 <<historyList[i].programName << " -> "
			 <<historyList[i].result << "\n";
	}
	system("pause");
}
