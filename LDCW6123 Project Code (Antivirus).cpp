#include<iostream>
#include<string>
#include<cstlib>

void mainMenu();

int main(){
	int choice = 0;
	
	while (choice != 8){
		system("cls");
		mainMenu();
		
		cout << "Enter Choice <1-8>: \n";
		cin >> choice;
		
		while (choice < 1 || choice > 8){
			cout << "Invalid Choice! Please Enter a number between 1-8.";
			cin >> choice;
		}
		
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
				cout << "Program Terminated\n";
				break;
		}
	}
	return 0;
}

//main menu
void mainMenu(){
	cout << "\n================== Simulated Antivirus ===================\n";
	cout << "\n";
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


