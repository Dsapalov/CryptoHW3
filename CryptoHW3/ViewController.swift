//
//  ViewController.swift
//  CryptoHW3
//
//  Created by Denis Sapalov on 05.11.2022.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var inputTextField: UITextField!
    @IBOutlet weak var outputTextView: UITextView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    @IBAction func hashIt() {
        guard let inputString = inputTextField.text else {
            let alert = UIAlertController(title: "Error", message: "Incorrect input data", preferredStyle: .alert)
            present(alert, animated: true, completion: nil)
            return
        }
        outputTextView.text = InternalSHA1.hexString(from: inputString)
    }
}
